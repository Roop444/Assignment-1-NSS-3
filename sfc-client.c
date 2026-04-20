#include "common.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: %s <inputfile>\n", argv[0]);
        return 1;
    }

    // 1. Read File
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) die("fopen");
    fseek(fp, 0, SEEK_END);
    long flen = ftell(fp);
    rewind(fp);
    unsigned char *plain = malloc(flen);
    fread(plain, 1, flen, fp);
    fclose(fp);

    // 2. Connect
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); // Change to Server IP
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("connect");

    // 3. GSS Auth
    OM_uint32 maj, min;
    gss_ctx_id_t gctx = GSS_C_NO_CONTEXT;
    gss_name_t target;
    gss_buffer_desc namebuf = { .value = "sfc@server.local", .length = 16 };
    gss_import_name(&min, &namebuf, GSS_C_NT_HOSTBASED_SERVICE, &target);

    gss_buffer_desc in = GSS_C_EMPTY_BUFFER, out = GSS_C_EMPTY_BUFFER;
    do {
        maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &gctx, target, GSS_C_NO_OID, 
                                   GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG, 0, NULL, &in, NULL, &out, NULL, NULL);
        if (out.length > 0) {
            send_token(fd, &out);
            gss_release_buffer(&min, &out);
        }
        if (maj == GSS_S_CONTINUE_NEEDED) recv_token(fd, &in);
    } while (maj == GSS_S_CONTINUE_NEEDED);

    if (maj != GSS_S_COMPLETE) die("GSS Complete failed");
    printf("Authenticated context established.\n");

    // 4. Secure Key Exchange (GSS-Wrap)
    unsigned char key[32];
    RAND_bytes(key, 32);
    gss_buffer_desc kbuf = { 32, key }, wrapped_k;
    gss_wrap(&min, gctx, 1, GSS_C_QOP_DEFAULT, &kbuf, NULL, &wrapped_k);
    send_token(fd, &wrapped_k);
    gss_release_buffer(&min, &wrapped_k);

    // 5. AES-GCM Encrypt
    unsigned char nonce[NONCE_LEN], tag[TAG_LEN];
    RAND_bytes(nonce, NONCE_LEN);
    unsigned char *cipher = malloc(flen);
    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ectx, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(ectx, cipher, &len, plain, flen);
    EVP_EncryptFinal_ex(ectx, cipher + len, &len);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ectx);

    // 6. Send Data
    uint32_t clen_n = htonl(flen);
    send_all(fd, &clen_n, 4);
    send_all(fd, nonce, NONCE_LEN);
    send_all(fd, cipher, flen);
    send_all(fd, tag, TAG_LEN);

    printf("Encrypted file sent.\n");
    close(fd);
    return 0;
}
