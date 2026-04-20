#include "common.h"

void die(const char *msg){
    perror(msg);
    exit(1);
}

int send_all(int fd, void *buf, size_t len){
    size_t done=0;
    while(done<len){
        int n=write(fd,(char*)buf+done,len-done);
        if(n<=0) return -1;
        done+=n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len){
    size_t done=0;
    while(done<len){
        int n=read(fd,(char*)buf+done,len-done);
        if(n<=0) return -1;
        done+=n;
    }
    return 0;
}

int send_token(int fd, gss_buffer_t tok){
    uint32_t n=htonl(tok->length);
    send_all(fd,&n,4);
    send_all(fd,tok->value,tok->length);
    return 0;
}

int recv_token(int fd, gss_buffer_t tok){
    uint32_t n;
    recv_all(fd,&n,4);
    n=ntohl(n);

    tok->length=n;
    tok->value=malloc(n);

    recv_all(fd,tok->value,n);
    return 0;
}

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
        NULL,NULL,NULL,NULL,NULL
    );

    if (maj != GSS_S_COMPLETE)
        die("gss_inquire_context");

    gss_display_name(&min, src, &n1, NULL);
    gss_display_name(&min, tgt, &n2, NULL);

    char buf[512];

    snprintf(buf, sizeof(buf), "%.*s|%.*s",
        (int)n1.length, (char*)n1.value,
        (int)n2.length, (char*)n2.value);

    SHA256((unsigned char*)buf, strlen(buf), key);

    gss_release_buffer(&min,&n1);
    gss_release_buffer(&min,&n2);
}
