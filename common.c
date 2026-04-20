#include "common.h"

void die(const char *msg) {
    perror(msg);
    exit(1);
}

int send_all(int fd, void *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, (char*)buf + done, len - done);
        if (n <= 0) return -1;
        done += n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, (char*)buf + done, len - done);
        if (n <= 0) return -1;
        done += n;
    }
    return 0;
}

int send_token(int fd, gss_buffer_t tok) {
    uint32_t n = htonl(tok->length);
    if (send_all(fd, &n, 4) < 0) return -1;
    if (send_all(fd, tok->value, tok->length) < 0) return -1;
    return 0;
}

int recv_token(int fd, gss_buffer_t tok) {
    uint32_t n;
    if (recv_all(fd, &n, 4) < 0) return -1;
    n = ntohl(n);

    tok->length = n;
    tok->value = malloc(n);
    if (!tok->value) return -1;

    if (recv_all(fd, tok->value, n) < 0) {
        free(tok->value);
        return -1;
    }
    return 0;
}
