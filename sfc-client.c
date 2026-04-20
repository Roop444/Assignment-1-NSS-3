#include "common.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s inputfile\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp)
        die("file");

    fseek(fp, 0, SEEK_END);
    long flen = ftell(fp);
    rewind(fp);

    unsigned char *plain = malloc(flen);
    fread(plain, 1, flen, fp);
    fclose(fp);

    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "192.168.1.30", &addr.sin_addr);   // server IP

    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    printf("Connected.\n");

    /* =========================
       PHASE 3 : GSSAPI AUTH
       ========================= */

    OM_uint32 maj, min;

    gss_ctx_id_t gctx = GSS_C_NO_CONTEXT;
    gss_name_t target;

    gss_buffer_desc namebuf;
    gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out = GSS_C_EMPTY_BUFFER;

    char service[] = "sfc@server.local";   // change hostname if needed

    namebuf.value = service;
    namebuf.length = strlen(service);

    maj = gss_import_name(
        &min,
        &namebuf,
        GSS_C_NT_HOSTBASED_SERVICE,
        &target
    );

    if (maj != GSS_S_COMPLETE)
        die("gss_import_name");

    do {
        maj = gss_init_sec_context(
            &min,
            GSS_C_NO_CREDENTIAL,
            &gctx,
            target,
            GSS_C_NO_OID,
            0,
            0,
            NULL,
            &in,
            NULL,
            &out,
            NULL,
            NULL
        );

        if (out.length > 0) {
            send_token(fd, &out);
            gss_release_buffer(&min, &out);
        }

        if (maj == GSS_S_CONTINUE_NEEDED) {
            recv_token(fd, &in);
        }

    } while (maj == GSS_S_CONTINUE_NEEDED);

    if (maj != GSS_S_COMPLETE)
        die("gss_init_sec_context");

    printf("Authenticated context established.\n");

    /* =========================
       PHASE 3 KEY DERIVATION
       ========================= */

    /* CLIENT SIDE */
    unsigned char key[32];
    RAND_bytes(key, 32); // Generate a fresh random file key
    
    gss_buffer_desc key_to_wrap, wrapped_key;
    key_to_wrap.value = key;
    key_to_wrap.length = 32;
    
    // Wrap the key using the Kerberos context (this provides confidentiality)
    maj = gss_wrap(&min, gctx, 1, GSS_C_QOP_DEFAULT, &key_to_wrap, NULL, &wrapped_key);
    if (maj != GSS_S_COMPLETE) die("gss_wrap failed");
    
    // Send the wrapped key to the server
    send_token(fd, &wrapped_key);
    gss_release_buffer(&min, &wrapped_key);

    /* =========================
       AES-256-GCM ENCRYPTION
       ========================= */

    unsigned char nonce[NONCE_LEN];
    RAND_bytes(nonce, NONCE_LEN);

    unsigned char *cipher = malloc(flen + 16);
    unsigned char tag[TAG_LEN];

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

    int len = 0;
    int clen = 0;

    EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ectx, NULL, NULL, key, nonce);

    EVP_EncryptUpdate(ectx, cipher, &len, plain, flen);
    clen = len;

    EVP_EncryptFinal_ex(ectx, cipher + len, &len);
    clen += len;

    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ectx);

    /* =========================
       SEND FILE
       ========================= */

    uint32_t n = htonl(clen);

    printf("Client nonce: ");
    for (int i = 0; i < NONCE_LEN; i++)
        printf("%02x", nonce[i]);
    printf("\n");

    send_all(fd, &n, 4);
    send_all(fd, nonce, NONCE_LEN);
    send_all(fd, cipher, clen);
    send_all(fd, tag, TAG_LEN);

    printf("Encrypted file sent.\n");

    close(fd);
    return 0;
}
