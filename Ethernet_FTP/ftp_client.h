#ifndef FTP_CLIENT_H
#define FTP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>

#define FTP_CTRL_SOCKET 0
#define FTP_DATA_SOCKET 1

typedef struct {
    char server_ip[16];
    uint16_t port;

    char username[32];
    char password[32];

    uint8_t debug;   // print all responses
} ftp_client_t;

// Core API
bool ftp_connect(ftp_client_t *ftp);
bool ftp_login(ftp_client_t *ftp);

bool ftp_download(ftp_client_t *ftp,
                  const char *remote_file,
                  void (*write_cb)(uint8_t *data, uint16_t len));

bool ftp_upload(ftp_client_t *ftp,
                const char *remote_file,
                uint8_t *data,
                uint32_t len);

void ftp_disconnect(ftp_client_t *ftp);

#endif