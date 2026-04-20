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

    /* Static Phase 2 key */
    unsigned char key[32] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32
    };

    unsigned char nonce[NONCE_LEN];
    RAND_bytes(nonce, NONCE_LEN);

    unsigned char *cipher = malloc(flen + 16);
    unsigned char tag[TAG_LEN];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    int len, clen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    EVP_EncryptUpdate(ctx, cipher, &len, plain, flen);
    clen = len;

    EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    clen += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);

    uint32_t n = htonl(clen);

    printf("Client nonce: ");
    for (int i = 0; i < 12; i++)
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
