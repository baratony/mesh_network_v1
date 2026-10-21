/* ==========================================================================
 * site_server.h -- the HTTP front of Core 0.
 *
 * This replaces the "Hello World" placeholder that used to live in
 * ethernet_setup.c. It is now a real, tiny web server:
 *
 *   - one W5500 socket (number 2, port 80) is kept in LISTEN state,
 *   - a browser connects to it and sends a request,
 *   - the request is accumulated across recv() calls until it is complete,
 *   - the path is looked up in the asset table and the file is streamed back,
 *     or, if it is an /action/... path, a handler in mesh_network_v1.c runs,
 *   - the socket is disconnected so it returns to LISTEN for the next request.
 *
 * It is deliberately non-blocking: http_server_poll() does at most one chunk
 * of work per call and main() calls it every 10 ms. Nothing here may block,
 * because Core 1 keeps receiving radio packets while Core 0 is serving.
 * ==========================================================================*/
#ifndef SITE_SERVER_H
#define SITE_SERVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Open the W5500 HTTP socket and put it into LISTEN state on port 80.
 * Call once, after init_w5500(). */
void http_server_init(void);

/* Do at most one step of work: read some request bytes, and answer if the
 * request is complete. Call repeatedly from the application loop. */
void http_server_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* SITE_SERVER_H */
