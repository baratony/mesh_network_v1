/* ==========================================================================
 * ftp_client.c -- the node's PERSISTENT STORAGE.
 *
 * Why the mesh needs a server at all: a Pico has ~hundreds of KB of RAM and
 * no storage that survives a reboot. So the node's whole idea of the world -
 * its neighbour list, the global connection graph, the RSA key ledger, its own
 * key pair - lives as files on an FTP server reached over the W5500 Ethernet.
 * Every protocol handler in radio.c is written as: download a file into a RAM
 * buffer, edit it, upload it back.
 *
 * This file is a hand-rolled, minimal FTP client over the wizchip/w5500
 * socket API. It implements only what the mesh uses: connect, login,
 * RETR (download) and STOR (upload), in passive mode.
 *
 * Two sockets are used at once, which is why ftp_client.h defines
 * FTP_CTRL_SOCKET 0 and FTP_DATA_SOCKET 1: FTP's control channel carries the
 * commands and replies, the data channel carries the file bytes. They are
 * separate TCP connections, so both must be open simultaneously.
 *
 * NOTE: this is not thread safe. Core 0 runs an HTTP server on the same
 * W5500, so every caller in main() wraps these calls in network_lock.
 * ==========================================================================*/
#include "ftp_client.h"
#include "wizchip_conf.h"
#include "socket.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pico/stdlib.h"


/* --- the three primitives everything else is built from ------------------ */

/* Write exactly len bytes, coping with the socket API's short writes.
 * A return of 0 means 'nothing accepted yet', so we wait rather than fail:
 * on a Pico the W5500 send path can legitimately stall. */
static int ftp_socket_send_all(int sock, const uint8_t *data, size_t len)
{
    size_t sent = 0;

    /* Loop until the whole buffer has gone out. Each iteration advances the
     * cursor by however many bytes the socket actually accepted. */
    while (sent < len) {
        int written = send(sock, (uint8_t *)(data + sent), len - sent);
        if (written > 0) {
            sent += (size_t)written;
            continue;
        }

        if (written == 0) {
            sleep_ms(5);
            continue;
        }

        return -1;   /* negative = a real socket error */
    }

    return 0;
}

/* FTP's wire protocol is text with CRLF terminators, so every command is
 * 'body' + CRLF. The CRLF is sent separately so the caller never has to
 * embed it in the string. */
static void ftp_send_cmd(int sock, const char *cmd)
{
    size_t len = strlen(cmd);
    ftp_socket_send_all(sock, (const uint8_t *)cmd, len);
    ftp_socket_send_all(sock, (const uint8_t *)"\r\n", 2);
}
                                                                                                                                       

/* Read one complete FTP reply, following the protocol's continuation rule.
 *
 * FTP replies are 'NNN text'. If the fourth character is a '-' the reply
 * continues on more lines, so we must keep reading until a line comes back as
 * 'NNN <space>'. That is the whole reason this function is a loop.
 *
 * Returns the numeric code, -1 on a socket error, -2 on timeout. Callers
 * compare the code against the expected one (230 login, 227 PASV, 150/125
 * transfer started, 226 transfer complete). */
static int ftp_read_reply(int sock, char *out, int maxlen, uint8_t debug)
{
    /* A hard deadline: a dead server must not stall the mesh forever, and
     * every caller of this runs on Core 1's receive loop. */
    absolute_time_t deadline = make_timeout_time_ms(2500);
    int final_code = -1;

    while (true) {
        if (time_reached(deadline)) {
            if (debug) {
                printf("[FTP] reply timed out\n");
            }
            return -2;
        }

        /* No bytes yet: wait. This is the only blocking point in the client,
         * and it is bounded by the deadline above. */
        if (getSn_RX_RSR(sock) <= 0) {
            sleep_ms(10);
            continue;
        }

        /* Accumulate one line, stopping at LF and dropping CR so the code
         * works on CRLF and bare-LF servers alike. */
        char line[256];
        int len = 0;
        while (len < (int)sizeof(line) - 1) {
            uint8_t ch = 0;
            int n = recv(sock, &ch, 1);
            if (n <= 0) {
                return -1;
            }

            if (ch == '\n') {
                break;
            }

            if (ch != '\r') {
                line[len++] = (char)ch;
            }
        }

        line[len] = 0;

        if (debug) {
            printf("[FTP REPLY] %s\n", line);
        }

        /* Recognise a status line: three digits at the start. Anything else
         * (a continuation line, server noise) is skipped by the outer loop. */
        if (len >= 3 && line[0] >= '0' && line[0] <= '9' &&
            line[1] >= '0' && line[1] <= '9' &&
            line[2] >= '0' && line[2] <= '9') {
            final_code = atoi(line);
            /* 'NNN-' means more lines follow; 'NNN ' means the reply is done. */
            if (len < 4 || line[3] != '-') {
                if (out && maxlen > 0) {
                    strncpy(out, line, maxlen - 1);
                    out[maxlen - 1] = 0;
                }
                return final_code;
            }
        }
    }
}


/* Open the CONTROL connection (socket 0) to the server named in the struct.
 * Called once from second_core_code() before anything else FTP-related runs;
 * if it fails, the node cannot join the mesh at all and Core 1 returns. */
bool ftp_connect(ftp_client_t *ftp)
{
    uint8_t ip[4];
    char buf[256];

    /* The address is stored as dotted text in the struct, but the socket API
     * wants four bytes, so parse it here. */
    sscanf(ftp->server_ip, "%hhu.%hhu.%hhu.%hhu",
           &ip[0], &ip[1], &ip[2], &ip[3]);

    /* Prepare the control socket as a TCP peer. */
    socket(FTP_CTRL_SOCKET, Sn_MR_TCP, 5000, 0);

    if(connect(FTP_CTRL_SOCKET, ip, ftp->port) != SOCK_OK)
        return false;

    /* Drain whatever greeting came back; the return value is ignored because
     * a raw TCP connect has no status to check. */
    ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);

    return true;
}

/* Send USER/PASS and confirm the server accepted them.
 *
 * The double check is deliberate: some servers answer USER with 331 'send the
 * password', others skip straight to 230 'logged in'. Both are success. */
bool ftp_login(ftp_client_t *ftp)
{
    char buf[256];

    // USER
    sprintf(buf, "USER %s", ftp->username);
    ftp_send_cmd(FTP_CTRL_SOCKET, buf);

    if(ftp_read_reply(FTP_CTRL_SOCKET, buf, 256, ftp->debug) != 331)
    {
        if(ftp_read_reply(FTP_CTRL_SOCKET, buf, 256, ftp->debug) != 230)
            return false;
    }

    // PASS
    sprintf(buf, "PASS %s", ftp->password);
    ftp_send_cmd(FTP_CTRL_SOCKET, buf);

    int code = ftp_read_reply(FTP_CTRL_SOCKET, buf, 256, ftp->debug);

    return (code == 230);
}


/* --- passive-mode negotiation -------------------------------------------
 * FTP's passive mode is the only usable mode here: the server, not the Pico,
 * picks the data connection's address and port. Servers disagree on which
 * dialect they speak, so both PASV (227) and EPSV (229) are implemented and
 * tried in turn by ftp_enter_pasv().
 * ------------------------------------------------------------------------- */

/* Parse the classic PASV reply: '... (h1,h2,h3,h4,port_hi,port_lo) ...'.
 * Note the port is transmitted as two bytes, which is why it is rebuilt with
 * a shift rather than read as a number. */
static int ftp_extract_pasv(const char *reply, uint8_t *ip, uint16_t *port)
{
    const char *start = strchr(reply, '(');
    const char *end = strchr(reply, ')');
    int h1, h2, h3, h4, p1, p2;

    if (!start || !end || end <= start) {
        return -1;
    }

    if (sscanf(start, "(%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        return -1;
    }

    /* Fill in the four address bytes and rebuild the 16-bit port. */
    ip[0] = (uint8_t)h1;
    ip[1] = (uint8_t)h2;
    ip[2] = (uint8_t)h3;
    ip[3] = (uint8_t)h4;
    *port = (uint16_t)((p1 << 8) | p2);
    return 0;
}

/* Parse the extended EPSV reply: '... (|||port|) ...'. EPSV reuses the
 * control connection's IP address, so only a port is given. */
static int ftp_extract_epsv(const char *reply, uint16_t *port)
{
    const char *start = strchr(reply, '(');
    const char *end = strchr(reply, ')');
    if (!start || !end || end <= start) {
        return -1;
    }

    int p = 0;
    if (sscanf(start, "(|||%d|)", &p) != 1) {
        return -1;
    }

    *port = (uint16_t)p;
    return 0;
}

/* Try PASV, then EPSV, and hand back the data connection's address.
 * Called at the start of every download and upload, i.e. once per file
 * transfer in the mesh protocol. */
static int ftp_enter_pasv(ftp_client_t *ftp, uint8_t *ip, uint16_t *port)
{
    char buf[256];
    uint8_t server_ip[4];
    int code;

    /* Kept aside so the EPSV branch, which does not send an address, can
     * reuse the control connection's. */
    sscanf(ftp->server_ip, "%hhu.%hhu.%hhu.%hhu",
           &server_ip[0], &server_ip[1], &server_ip[2], &server_ip[3]);

    ftp_send_cmd(FTP_CTRL_SOCKET, "PASV");
    code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
    if (code == 227 && ftp_extract_pasv(buf, ip, port) == 0) {
        if (ftp->debug) {
            printf("[FTP] PASV -> %u.%u.%u.%u:%u\n", ip[0], ip[1], ip[2], ip[3], *port);
        }
        return 0;
    }

    /* Fall through: this server speaks the extended dialect instead. */
    ftp_send_cmd(FTP_CTRL_SOCKET, "EPSV");
    code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
    if (code == 229 && ftp_extract_epsv(buf, port) == 0) {
        memcpy(ip, server_ip, sizeof(server_ip));
        if (ftp->debug) {
            printf("[FTP] EPSV -> %u.%u.%u.%u:%u\n", ip[0], ip[1], ip[2], ip[3], *port);
        }
        return 0;
    }

    if (ftp->debug) {
        printf("[FTP] Failed to parse passive reply: %s\n", buf);
    }
    return -1;
}


/* -------------------------------------------------------------------------
 * THE TWO OPERATIONS EVERY PROTOCOL HANDLER IN radio.c USES
 *
 * download: ask for a file, then stream its bytes into write_cb(). The
 * callback is what lets radio.c keep the file in one static buffer without
 * this client ever allocating one - the file never has to fit in RAM twice.
 * ------------------------------------------------------------------------- */
bool ftp_download(ftp_client_t *ftp,
                  const char *remote_file,
                  void (*write_cb)(uint8_t *data, uint16_t len))
{
    enum
    {
        FTP_DOWNLOAD_RETRIES = 3
    };

    char buf[256];
    uint8_t data[1024];

    for (int attempt = 0; attempt <= FTP_DOWNLOAD_RETRIES; ++attempt)
    {
        uint8_t ip[4];
        uint16_t port;

        if (ftp_enter_pasv(ftp, ip, &port) != 0)
            return false;

        /* Open the DATA connection (socket 1) - separate from the control one. */
        socket(FTP_DATA_SOCKET, Sn_MR_TCP, 6000, 0);

        if (connect(FTP_DATA_SOCKET, ip, port) != SOCK_OK)
            return false;

        snprintf(buf, sizeof(buf), "RETR %s", remote_file);
        ftp_send_cmd(FTP_CTRL_SOCKET, buf);

        int transfer_code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
        if (transfer_code == 550)
        {
            close(FTP_DATA_SOCKET);

            if (attempt < FTP_DOWNLOAD_RETRIES)
            {
                if (ftp->debug)
                    printf("[FTP] %s unavailable (550); retrying (%d/%d)\n",
                           remote_file,
                           attempt + 1,
                           FTP_DOWNLOAD_RETRIES);
                sleep_ms(100);
                continue;
            }

            if (ftp->debug)
                printf("[FTP] Giving up downloading %s after %d retries\n",
                       remote_file,
                       FTP_DOWNLOAD_RETRIES);
            return false;
        }

        if (transfer_code != 125 && transfer_code != 150)
        {
            close(FTP_DATA_SOCKET);
            if (ftp->debug)
                printf("[FTP] RETR %s rejected (reply code %d)\n",
                       remote_file,
                       transfer_code);
            return false;
        }

        /* Stream file bytes into the caller's bounded buffer. */
        while (true)
        {
            int len = recv(FTP_DATA_SOCKET, data, sizeof(data));

            if (len <= 0)
                break;

            write_cb(data, (uint16_t)len);
        }

        disconnect(FTP_DATA_SOCKET);

        /* Consume the closing 'transfer complete' reply so the control channel
         * stays in sync for the next command. */
        int completion_code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
        return completion_code == 226 || completion_code == 250;
    }

    return false;
}


/* Upload a whole buffer that is already in RAM - the shape every handler in
 * radio.c uses, because the file it writes is exactly the buffer it edited
 * after a download. */
bool ftp_upload(ftp_client_t *ftp,
                const char *remote_file,
                uint8_t *data,
                uint32_t len)
{
    char buf[256];
    uint8_t ip[4];
    uint16_t port;
    uint32_t sent = 0;

    if (ftp_enter_pasv(ftp, ip, &port) != 0) {
        if (ftp->debug) {
            printf("[FTP] PASV setup failed\n");
        }
        return false;
    }

    socket(FTP_DATA_SOCKET, Sn_MR_TCP, 6000, 0);

    if (connect(FTP_DATA_SOCKET, ip, port) != SOCK_OK) {
        if (ftp->debug) {
            printf("[FTP] Data socket connect failed to %u.%u.%u.%u:%u\n", ip[0], ip[1], ip[2], ip[3], port);  
        }
        return false;
    }

    /* Binary mode is mandatory: without TYPE I a server may translate bytes
     * and corrupt the .bin files (the graph and the key ledger are binary). */
    ftp_send_cmd(FTP_CTRL_SOCKET, "TYPE I");
    ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);

    sprintf(buf, "STOR %s", remote_file);
    ftp_send_cmd(FTP_CTRL_SOCKET, buf);

    /* 150/125 mean 'ready for the data'; anything else means the server
     * refused the file, so the data socket must be released before failing. */
    int transfer_code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
    if (transfer_code != 150 && transfer_code != 125) {
        close(FTP_DATA_SOCKET);
        return false;
    }

    /* Push the buffer out, coping with short writes the same way
     * ftp_socket_send_all() does. The small sleep keeps the W5500 from being
     * saturated by back-to-back sends. */
    while (sent < len) {
        int written = send(FTP_DATA_SOCKET, data + sent, len - sent);
        if (written > 0) {
            sent += (uint32_t)written;
            sleep_ms(2);
            continue;
        }
        if (written == 0) {
            sleep_ms(5);
            continue;
        }

        disconnect(FTP_DATA_SOCKET);
        return false;
    }
    
    /* Let the server finish writing before closing the data connection, then
     * wait again before reading the closing reply. */
    sleep_ms(50);
    disconnect(FTP_DATA_SOCKET);
    sleep_ms(50);

    int final_code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
    if (final_code != 226 && final_code != 250 && final_code != 200) {
        if (ftp->debug) {
            printf("[FTP] Upload of %s did not complete (reply code %d)\n",
                   remote_file,
                   final_code);
        }
        return false;
    }

    return true;
}

/* End the session and release the control socket. radio.c calls this when an
 * upload fails, so the next attempt reconnects from scratch. */
void ftp_disconnect(ftp_client_t *ftp)
{
    ftp_send_cmd(FTP_CTRL_SOCKET, "QUIT");

    char buf[128];
    ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);

    close(FTP_CTRL_SOCKET);
}