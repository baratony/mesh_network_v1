/* ==========================================================================
 * site_server.c -- implementation of the node's web front.
 *
 * It owns the third W5500 socket (0 and 1 belong to the FTP client that Core
 * 1 uses for the mesh ledger). Because the two cores share one W5500, main()
 * keeps this server outside the network_lock that guards FTP: the W5500 can
 * only do one thing at a time, and a browser request must never be blocked by
 * a file transfer.
 * ==========================================================================*/
#include "site_server.h"
#include "site_assets.h"
#include "site_actions.h"

#include "socket.h"
#include "wizchip_conf.h"

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"

#define HTTP_SOCKET       2
#define HTTP_PORT         80

/* A request is assembled across several recv() calls: the W5500 hands back
 * whatever arrived since the last call, not whole requests. */
#define SITE_REQUEST_MAX          1600
#define SITE_SEND_CHUNK           512
#define SITE_QUERY_ARG_MAX        256

/* --------------------------------------------------------------------------
 * Request state
 * -------------------------------------------------------------------------- */

static char request_buffer[SITE_REQUEST_MAX];
static size_t request_length;

/* Decoded copies of the query arguments, so the handlers always receive a
 * plain, NUL-terminated C string of bounded length. */
static char arg_first[SITE_QUERY_ARG_MAX];

/* A POST body is not a query argument: a letter may be much longer than one,
 * so it gets its own buffer, sized like the request itself. */
static char arg_body[SITE_REQUEST_MAX];

/* --------------------------------------------------------------------------
 * Writing the response
 *
 * send() on a W5500 accepts at most a small block per call and may report
 * SOCK_BUSY, meaning "not now". This loop copes with both: it advances only
 * by what was really accepted and retries after a short sleep. A hard error
 * aborts, which is the only way a page can fail to load.
 * -------------------------------------------------------------------------- */

static int site_send_all(const char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length)
    {
        size_t chunk = length - sent;
        if (chunk > SITE_SEND_CHUNK)
            chunk = SITE_SEND_CHUNK;

        int32_t written = send(HTTP_SOCKET,
                               (uint8_t *)(data + sent),
                               (uint16_t)chunk);

        if (written > 0)
        {
            sent += (size_t)written;
            continue;
        }

        if (written == SOCK_BUSY || written == 0)
        {
            sleep_ms(2);
            continue;
        }

        return -1;
    }

    return 0;
}

/* Send a status line and nothing else: used for unknown paths and for the
 * empty replies an unimplemented action produces. */
static void site_send_status(int code, const char *body)
{
    const char *reason;

    if (code == 200)
        reason = "OK";
    else if (code == 404)
        reason = "Not Found";
    else
        reason = "Error";

    char header[256];

    int length = snprintf(header, sizeof(header),
                          "HTTP/1.1 %d %s\r\n"
                          "Content-Type: text/plain; charset=utf-8\r\n"
                          "Content-Length: %u\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          code,
                          reason,
                          (unsigned)(body ? strlen(body) : 0u),
                          body ? body : "");

    if (length < 0)
        return;

    if ((size_t)length >= sizeof(header))
        length = (int)sizeof(header) - 1;

    site_send_all(header, (size_t)length);
}

/* Serve one document from the asset table: headers first, then the bytes in
 * SITE_SEND_CHUNK-sized pieces, so a 15 kB page never needs a 15 kB buffer. */
static void site_send_asset(const site_asset_t *asset)
{
    char header[256];

    int length = snprintf(header, sizeof(header),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: %s\r\n"
                          "Content-Length: %u\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          asset->content_type,
                          (unsigned)asset->length);

    if (length < 0)
        return;

    if ((size_t)length >= sizeof(header))
        length = (int)sizeof(header) - 1;

    if (site_send_all(header, (size_t)length) < 0)
    {
        printf("[HTTP] header send failed for %s\n", asset->name);
        return;
    }

    if (site_send_all(asset->body, asset->length) < 0)
        printf("[HTTP] body send failed for %s\n", asset->name);
}

/* --------------------------------------------------------------------------
 * Reading the request
 *
 * The buffer is complete once the blank line that ends the headers has been
 * seen, plus however many body bytes Content-Length promised. Until then
 * http_server_poll() keeps collecting and answers nothing.
 * -------------------------------------------------------------------------- */

static int site_request_complete(void)
{
    if (request_length == 0)
        return 0;

    const char *separator = strstr(request_buffer, "\r\n\r\n");

    /* No header terminator yet, and no room for more: give up on what we have
     * rather than stall the browser forever. */
    if (separator == NULL)
        return request_length >= sizeof(request_buffer) ? 1 : 0;

    /* No body was promised. */
    if (separator[4] == '\0')
        return 1;

    const char *content_length = strstr(request_buffer, "Content-Length:");
    if (content_length == NULL || content_length > separator)
        return 1; /* a browser that sent no Content-Length sends no body */

    unsigned int declared = 0;
    if (sscanf(content_length + 15, "%u", &declared) != 1)
        return 1;

    size_t body_present = request_length - (size_t)(separator - request_buffer) - 4u;

    return (body_present >= declared) ? 1 : 0;
}

/* --------------------------------------------------------------------------
 * Extracting one query argument
 *
 * Query values are percent-escaped by the browser (%20 for a space, %40 for
 * @, ...) and use '+' for spaces, so they have to be decoded before a handler
 * sees them. Anything malformed is copied through unchanged.
 * -------------------------------------------------------------------------- */

static int site_decode_arg(const char *query,
                           const char *name,
                           char *out,
                           size_t out_size)
{
    out[0] = '\0';

    if (query == NULL || name == NULL || out_size == 0)
        return 0;

    char key[32];
    if (snprintf(key, sizeof(key), "%s=", name) >= (int)sizeof(key))
        return 0;

    const char *at = strstr(query, key);
    if (at == NULL)
        return 0;

    at += strlen(key);

    size_t written = 0;

    while (*at != '\0' && *at != '&' && written + 1u < out_size)
    {
        if (*at == '%')
        {
            unsigned int value = 0;
            if (strlen(at) >= 3u && sscanf(at + 1, "%2x", &value) == 1)
            {
                out[written++] = (char)value;
                at += 3;
                continue;
            }
        }

        out[written++] = (*at == '+') ? ' ' : *at;
        ++at;
    }

    out[written] = '\0';
    return 1;
}

/* --------------------------------------------------------------------------
 * The request line
 *
 * A browser sends "GET /path HTTP/1.1", but the W5500's LISTEN mode can hand
 * back only the path. Both shapes are accepted: take the first token that
 * starts with '/', otherwise the token after the method.
 * -------------------------------------------------------------------------- */

static void site_dispatch(void)
{
    char path[256];
    size_t copied = 0;

    const char *cursor = request_buffer;

    /* Skip an optional method, i.e. anything before the first '/'. */
    const char *slash = strchr(request_buffer, '/');
    if (slash != NULL)
        cursor = slash;
    else
    {
        const char *space = strchr(request_buffer, ' ');
        if (space != NULL)
            cursor = space + 1;
    }

    /* Copy up to the first space or '?', which is the path proper. */
    while (*cursor != '\0' && *cursor != ' ' && copied + 1u < sizeof(path))
        path[copied++] = *cursor++;

    path[copied] = '\0';

    /* A bare "/" or an empty path is the home page. */
    if (path[0] == '\0' || strcmp(path, "/") == 0)
    {
        site_send_asset(site_find_asset("/"));
        return;
    }

    /* Everything after '?' is the argument list of an action. */
    static const char site_no_query[] = "";

    char *query = strchr(path, '?');
    if (query != NULL)
    {
        *query = '\0';
        ++query;
    }
    else
        query = (char *)site_no_query;

    /* --- 1. a real file wins first -------------------------------------- */
    const site_asset_t *asset = site_find_asset(path);
    if (asset != NULL)
    {
        site_send_asset(asset);
        return;
    }

    /* --- 2. otherwise it is a button press ------------------------------ */
    if (strncmp(path, "/action/", 8) != 0)
    {
        printf("[HTTP] 404 %s\n", path);
        site_send_status(404, "This node has no such page.");
        return;
    }

    const char *action = path + 8;

    /* The POST body, if any, follows the blank line. */
    const char *separator = strstr(request_buffer, "\r\n\r\n");
    const char *body = (separator != NULL) ? (separator + 4) : "";

    /* Each branch decodes only the arguments that action uses, then calls its
     * handler. The handlers live in mesh_network_v1.c and are intentionally
     * empty for now: pressing the button is wired up, what it does is not. */
    if (strcmp(action, "discussion_send") == 0)
    {
        site_decode_arg(query, "message", arg_first, sizeof(arg_first));
        site_action_discussion_send(arg_first);
    }
    else if (strcmp(action, "post_send") == 0)
    {
        site_decode_arg(query, "recipient", arg_first, sizeof(arg_first));

        size_t body_length = strlen(body);
        if (body_length >= sizeof(arg_body))
            body_length = sizeof(arg_body) - 1u;
        memcpy(arg_body, body, body_length);
        arg_body[body_length] = '\0';

        site_action_post_send(arg_first, arg_body);
    }
    else if (strcmp(action, "post_refresh") == 0)
        site_action_post_refresh();
    else if (strcmp(action, "post_folder") == 0)
    {
        site_decode_arg(query, "folder", arg_first, sizeof(arg_first));
        site_action_post_show_folder(arg_first);
    }
    else if (strcmp(action, "compose_open") == 0)
        site_action_compose_open();
    else if (strcmp(action, "compose_toggle") == 0)
        site_action_compose_toggle();
    else if (strcmp(action, "node_reset") == 0)
        site_action_node_reset();
    else if (strcmp(action, "keys_regenerate") == 0)
        site_action_keys_regenerate();
    else
    {
        printf("[HTTP] unknown action %s\n", action);
        site_send_status(404, "Unknown action.");
        return;
    }

    /* An action has no page of its own; the browser keeps showing the page it
     * came from, so a bare 200 is the correct answer. */
    site_send_status(200, "");
}

/* --------------------------------------------------------------------------
 * Public entry points, called from main() on Core 0
 * -------------------------------------------------------------------------- */

void http_server_init(void)
{
    /* Put the socket in TCP mode on port 80, then into LISTEN state. In this
     * mode the W5500 waits for a browser to connect to this node's own IP;
     * there is no connect() to a remote address, because the browser IS the
     * remote end. */
    int8_t result = socket(HTTP_SOCKET, Sn_MR_TCP, HTTP_PORT, 0);
    if (result < 0)
    {
        printf("[HTTP] socket open failed: %d\n", (int)result);
        return;
    }

    if (listen(HTTP_SOCKET) != SOCK_OK)
    {
        printf("[HTTP] listen failed\n");
        return;
    }

    request_length = 0;

    printf("[HTTP] site server listening on port %u\n", HTTP_PORT);
}

void http_server_poll(void)
{
    switch (getSn_SR(HTTP_SOCKET))
    {
        case SOCK_ESTABLISHED:
        {
            /* A browser is connected. Append whatever arrived since last time. */
            if (getSn_RX_RSR(HTTP_SOCKET) > 0)
            {
                size_t room = sizeof(request_buffer) - request_length;
                if (room == 0)
                {
                    /* Overrun: answer with what we have and start over. */
                    site_dispatch();
                    request_length = 0;
                    disconnect(HTTP_SOCKET);
                    break;
                }

                int32_t received = recv(HTTP_SOCKET,
                                        (uint8_t *)(request_buffer + request_length),
                                        (uint16_t)(room < SITE_SEND_CHUNK ? room : SITE_SEND_CHUNK));

                if (received > 0)
                {
                    request_length += (size_t)received;
                    request_buffer[request_length] = '\0';

                    if (site_request_complete())
                    {
                        site_dispatch();
                        request_length = 0;

                        /* Hand the socket back so it returns to LISTEN and the
                         * next request - a page reload, or the next button -
                         * can be accepted. */
                        disconnect(HTTP_SOCKET);
                    }
                }
            }
            break;
        }

        case SOCK_CLOSE_WAIT:
            disconnect(HTTP_SOCKET);
            break;

        case SOCK_CLOSED:
            http_server_init();
            break;

        default:
            /* SOCK_LISTEN / SOCK_BUSY: idle, nothing to do this round. */
            break;
    }
}
