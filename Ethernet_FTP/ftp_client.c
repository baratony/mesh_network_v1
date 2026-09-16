#include "ftp_client.h"
#include "wizchip_conf.h"
#include "socket.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pico/stdlib.h"


static int ftp_socket_send_all(int sock, const uint8_t *data, size_t len)
{
    size_t sent = 0;

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

        return -1;
    }

    return 0;
}

static void ftp_send_cmd(int sock, const char *cmd)
{
    size_t len = strlen(cmd);
    ftp_socket_send_all(sock, (const uint8_t *)cmd, len);
    ftp_socket_send_all(sock, (const uint8_t *)"\r\n", 2);
}
                                                                                                                                       

static int ftp_read_reply(int sock, char *out, int maxlen, uint8_t debug)
{
    absolute_time_t deadline = make_timeout_time_ms(2500);
    int final_code = -1;

    while (true) {
        if (time_reached(deadline)) {
            if (debug) {
                printf("[FTP] reply timed out\n");
            }
            return -2;
        }

        if (getSn_RX_RSR(sock) <= 0) {
            sleep_ms(10);
            continue;
        }

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

        if (len >= 3 && line[0] >= '0' && line[0] <= '9' &&
            line[1] >= '0' && line[1] <= '9' &&
            line[2] >= '0' && line[2] <= '9') {
            final_code = atoi(line);
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


bool ftp_connect(ftp_client_t *ftp)
{
    uint8_t ip[4];
    char buf[256];

    sscanf(ftp->server_ip, "%hhu.%hhu.%hhu.%hhu",
           &ip[0], &ip[1], &ip[2], &ip[3]);

    socket(FTP_CTRL_SOCKET, Sn_MR_TCP, 5000, 0);

    if(connect(FTP_CTRL_SOCKET, ip, ftp->port) != SOCK_OK)
        return false;

    ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);

    return true;
}


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

    ip[0] = (uint8_t)h1;
    ip[1] = (uint8_t)h2;
    ip[2] = (uint8_t)h3;
    ip[3] = (uint8_t)h4;
    *port = (uint16_t)((p1 << 8) | p2);
    return 0;
}

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

static int ftp_enter_pasv(ftp_client_t *ftp, uint8_t *ip, uint16_t *port)
{
    char buf[256];
    uint8_t server_ip[4];
    int code;

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


bool ftp_download(ftp_client_t *ftp,
                  const char *remote_file,
                  void (*write_cb)(uint8_t *data, uint16_t len))
{
    char buf[256];
    uint8_t ip[4];
    uint16_t port;

    // Enter PASV
    ftp_enter_pasv(ftp, ip, &port);

    // Open data socket
    socket(FTP_DATA_SOCKET, Sn_MR_TCP, 6000, 0);

    if (connect(FTP_DATA_SOCKET, ip, port) != SOCK_OK) {
        return false;
    }

    // Send RETR command
    sprintf(buf, "RETR %s", remote_file);
    ftp_send_cmd(FTP_CTRL_SOCKET, buf);

    ftp_read_reply(FTP_CTRL_SOCKET, buf, 256, ftp->debug);

    // Stream file
    uint8_t data[1024];

    while(1)
    {
        int len = recv(FTP_DATA_SOCKET, data, 1024);

        if(len <= 0)
            break;

        write_cb(data, len);
    }

    disconnect(FTP_DATA_SOCKET);

    ftp_read_reply(FTP_CTRL_SOCKET, buf, 256, ftp->debug);

    return true;
}


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

    ftp_send_cmd(FTP_CTRL_SOCKET, "TYPE I");
    ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);

    sprintf(buf, "STOR %s", remote_file);
    ftp_send_cmd(FTP_CTRL_SOCKET, buf);

    int transfer_code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
    if (transfer_code != 150 && transfer_code != 125) {
        close(FTP_DATA_SOCKET);
        return false;
    }

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
    
    sleep_ms(50);
    disconnect(FTP_DATA_SOCKET);
    sleep_ms(50);

    int final_code = ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);
    printf("%d", final_code);
    if (final_code != 226 && final_code != 250 && final_code != 200 && final_code != -2) {
        return false;
    }

    return true;
}


void ftp_disconnect(ftp_client_t *ftp)
{
    ftp_send_cmd(FTP_CTRL_SOCKET, "QUIT");

    char buf[128];
    ftp_read_reply(FTP_CTRL_SOCKET, buf, sizeof(buf), ftp->debug);

    close(FTP_CTRL_SOCKET);
}