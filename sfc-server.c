#include "common.h"

int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY };
    bind(sfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sfd, 5);
    printf("Server listening on %d\n", PORT);
    int cfd = accept(sfd, NULL, NULL);

    // 1. GSS Auth
    OM_uint32 maj, min;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in = GSS_C_EMPTY_BUFFER, out = GSS_C_EMPTY_BUFFER;
    do {
        recv_token(cfd, &in);
        maj = gss_accept_sec_context(&min, &ctx, GSS_C_NO_CREDENTIAL, &in, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &out, NULL, NULL, NULL);
        if (out.length > 0) {
            send_token(cfd, &out);
            gss_release_buffer(&min, &out);
        }
        free(in.value);
    } while (maj == GSS_S_CONTINUE_NEEDED);

    if (maj != GSS_S_COMPLETE) die("GSS Accept failed");
    printf("Authenticated context established.\n");

    // 2. Unwrap Key
    gss_buffer_desc wrapped_k, unwrapped_k;
    recv_token(cfd, &wrapped_k);
    int conf;
    gss_unwrap(&min, ctx, &wrapped_k, &unwrapped_k, &conf, NULL);
    unsigned char key[32];
    memcpy(key, unwrapped_k.value, 32);
    gss_release_buffer(&min, &unwrapped_k);
    free(wrapped_k.value);

    // 3. Receive Payload
    uint32_t n;
    recv_all(cfd, &n, 4);
    int clen = ntohl(n);
    unsigned char nonce[NONCE_LEN], tag[TAG_LEN];
    unsigned char *cipher = malloc(clen);
    recv_all(cfd, nonce, NONCE_LEN);
    recv_all(cfd, cipher, clen);
    recv_all(cfd, tag, TAG_LEN);

    // 4. Decrypt
    unsigned char *plain = malloc(clen);
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
    int len, ret;
    EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_DecryptInit_ex(dctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(dctx, plain, &len, cipher, clen);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    ret = EVP_DecryptFinal_ex(dctx, plain + len, &len);
    EVP_CIPHER_CTX_free(dctx);

    if (ret <= 0) {
        printf("TAG VERIFY FAILED\n");
    } else {
        FILE *fp = fopen("received.out", "wb");
        fwrite(plain, 1, clen, fp);
        fclose(fp);
        printf("File received safely.\n");
    }

    close(cfd);
    close(sfd);
    return 0;
}
