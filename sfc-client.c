#include "common.h"

int main(int argc,char **argv){

if(argc!=2){
    printf("usage: %s inputfile\n",argv[0]);
    return 1;
}

FILE *fp=fopen(argv[1],"rb");
if(!fp) die("file");

fseek(fp,0,SEEK_END);
long flen=ftell(fp);
rewind(fp);

unsigned char *plain=malloc(flen);
fread(plain,1,flen,fp);
fclose(fp);

int fd=socket(AF_INET,SOCK_STREAM,0);

struct sockaddr_in addr;
addr.sin_family=AF_INET;
addr.sin_port=htons(PORT);
inet_pton(AF_INET,"192.168.1.12",&addr.sin_addr);   /* change */

connect(fd,(struct sockaddr*)&addr,sizeof(addr));

printf("Connected.\n");

/* GSS AUTH */

OM_uint32 maj,min;
gss_ctx_id_t ctx=GSS_C_NO_CONTEXT;

gss_name_t target;
gss_buffer_desc namebuf;

char service[]="sfc@ssh.local";   /* change host */

namebuf.value=service;
namebuf.length=strlen(service);

gss_import_name(&min,&namebuf,GSS_C_NT_HOSTBASED_SERVICE,&target);

gss_buffer_desc in=GSS_C_EMPTY_BUFFER;
gss_buffer_desc out=GSS_C_EMPTY_BUFFER;

do{
    maj=gss_init_sec_context(
        &min,
        GSS_C_NO_CREDENTIAL,
        &ctx,
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

    if(out.length>0){
        send_token(fd,&out);
        gss_release_buffer(&min,&out);
    }

    if(maj==GSS_S_CONTINUE_NEEDED)
        recv_token(fd,&in);

}while(maj==GSS_S_CONTINUE_NEEDED);

if(maj!=GSS_S_COMPLETE) die("gss_init_sec_context");

printf("Authenticated context established.\n");

/* derive key */

unsigned char key[32];
derive_key(ctx,key);

/* encrypt */

unsigned char nonce[NONCE_LEN];
RAND_bytes(nonce,NONCE_LEN);

unsigned char *cipher=malloc(flen+16);
unsigned char tag[TAG_LEN];

EVP_CIPHER_CTX *ectx=EVP_CIPHER_CTX_new();

int len=0,clen=0;

EVP_EncryptInit_ex(ectx,EVP_aes_256_gcm(),NULL,NULL,NULL);
EVP_CIPHER_CTX_ctrl(ectx,EVP_CTRL_GCM_SET_IVLEN,NONCE_LEN,NULL);
EVP_EncryptInit_ex(ectx,NULL,NULL,key,nonce);

EVP_EncryptUpdate(ectx,cipher,&len,plain,flen);
clen=len;

EVP_EncryptFinal_ex(ectx,cipher+len,&len);
clen+=len;

EVP_CIPHER_CTX_ctrl(ectx,EVP_CTRL_GCM_GET_TAG,TAG_LEN,tag);

EVP_CIPHER_CTX_free(ectx);

/* send file */

uint32_t n=htonl(clen);

send_all(fd,&n,4);
send_all(fd,nonce,NONCE_LEN);
send_all(fd,cipher,clen);
send_all(fd,tag,TAG_LEN);

printf("Encrypted file sent.\n");

close(fd);
return 0;
}
