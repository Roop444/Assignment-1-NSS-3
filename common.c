/* =========================
   common.c
   ========================= */
#include "common.h"

void die(const char *msg)
{
    perror(msg);
    exit(1);
}

void gss_die(const char *msg, OM_uint32 maj, OM_uint32 min)
{
    printf("%s failed (maj=%u min=%u)\n", msg, maj, min);
    exit(1);
}

int send_all(int fd, void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        int n = write(fd, (char *)buf + done, len - done);
        if (n <= 0)
            return -1;
        done += n;
    }

    return 0;
}

int recv_all(int fd, void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        int n = read(fd, (char *)buf + done, len - done);
        if (n <= 0)
            return -1;
        done += n;
    }

    return 0;
}

int send_token(int fd, gss_buffer_t tok)
{
    uint32_t n = htonl(tok->length);

    send_all(fd, &n, 4);
    send_all(fd, tok->value, tok->length);

    return 0;
}

int recv_token(int fd, gss_buffer_t tok)
{
    uint32_t n;

    recv_all(fd, &n, 4);
    n = ntohl(n);

    tok->length = n;
    tok->value = malloc(n);

    recv_all(fd, tok->value, n);

    return 0;
}

/* Portable Phase 3 key derivation */
void derive_key(gss_ctx_id_t ctx, unsigned char key[32])
{
    OM_uint32 maj, min;

    gss_buffer_desc in;
    gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;

    char label[] = "SFC_SESSION_KEY";

    in.value = label;
    in.length = strlen(label);

    maj = gss_get_mic(
        &min,
        ctx,
        GSS_C_QOP_DEFAULT,
        &in,
        &mic
    );

    if (maj != GSS_S_COMPLETE)
        gss_die("gss_get_mic", maj, min);

    SHA256((unsigned char *)mic.value, mic.length, key);

    gss_release_buffer(&min, &mic);
}
