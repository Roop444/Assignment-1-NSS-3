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

    gss_name_t src, tgt;
    gss_buffer_desc n1 = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc n2 = GSS_C_EMPTY_BUFFER;

    maj = gss_inquire_context(
        &min,
        ctx,
        &src,
        &tgt,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (maj != GSS_S_COMPLETE)
        gss_die("gss_inquire_context", maj, min);

    gss_display_name(&min, src, &n1, NULL);
    gss_display_name(&min, tgt, &n2, NULL);

    char a[256], b[256];

    snprintf(a, sizeof(a), "%.*s",
        (int)n1.length, (char *)n1.value);

    snprintf(b, sizeof(b), "%.*s",
        (int)n2.length, (char *)n2.value);

    /* force same order both sides */
    char buf[600];

    if (strcmp(a, b) < 0)
        snprintf(buf, sizeof(buf), "%s|%s|SFCv1", a, b);
    else
        snprintf(buf, sizeof(buf), "%s|%s|SFCv1", b, a);

    SHA256((unsigned char *)buf, strlen(buf), key);

    gss_release_buffer(&min, &n1);
    gss_release_buffer(&min, &n2);
}
