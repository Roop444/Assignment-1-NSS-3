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

void derive_key(gss_ctx_id_t ctx, unsigned char key[32]) {
    OM_uint32 maj, min;
    gss_buffer_desc label = { 10, "sfc-aes-key" }; // Constant string
    gss_buffer_desc prf_out = GSS_C_EMPTY_BUFFER;

    // This extracts 32 bytes of entropy based on the Kerberos session secret
    maj = gss_pseudo_random(&min, ctx, GSS_C_PRF_KEY_FULL, &label, 32, &prf_out);

    if (maj != GSS_S_COMPLETE) {
        // Fallback: Some older MIT Kerberos versions use gss_get_mic/gss_verify_mic 
        // to check context integrity, but gss_pseudo_random is the standard way.
        die("gss_pseudo_random failed");
    }

    memcpy(key, prf_out.value, 32);
    gss_release_buffer(&min, &prf_out);
}
