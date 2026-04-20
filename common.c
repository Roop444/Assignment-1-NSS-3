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

#include <gssapi/gssapi_krb5.h> // Necessary for lucid context structures

void derive_key(gss_ctx_id_t ctx, unsigned char key[32]) {
    OM_uint32 maj, min;
    void *lucid_ctx = NULL;
    
    // 1. Export the "Lucid" context (internal K5 structures)
    maj = gss_krb5_export_lucid_sec_context(&min, &ctx, 1, &lucid_ctx);
    if (maj != GSS_S_COMPLETE) die("export_lucid failed");

    gss_krb5_lucid_context_v1_t *lctx = (gss_krb5_lucid_context_v1_t *)lucid_ctx;

    // 2. Access the actual session key negotiated by Kerberos
    // Depending on the version, it's usually lctx->rfc4537_export_key or lctx->key
    if (lctx->protocol == 1) {
        // Use the session key data to create your AES key
        SHA256(lctx->key.data, lctx->key.length, key);
    }

    // 3. Clean up (Very important for security!)
    gss_krb5_free_lucid_sec_context(&min, lucid_ctx);
}
