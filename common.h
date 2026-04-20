/* =========================
   common.h
   ========================= */
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <gssapi/gssapi.h>

#define PORT 5555
#define NONCE_LEN 12
#define TAG_LEN 16

void die(const char *msg);
void gss_die(const char *msg, OM_uint32 maj, OM_uint32 min);

int send_all(int fd, void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);

int send_token(int fd, gss_buffer_t tok);
int recv_token(int fd, gss_buffer_t tok);

void derive_key(gss_ctx_id_t ctx, unsigned char key[32]);

#endif
