#include "common.h"



int main(){



int sfd=socket(AF_INET,SOCK_STREAM,0);



struct sockaddr_in addr;

addr.sin_family=AF_INET;

addr.sin_port=htons(PORT);

addr.sin_addr.s_addr=INADDR_ANY;



bind(sfd,(struct sockaddr*)&addr,sizeof(addr));

listen(sfd,5);



printf("Server listening on %d\n",PORT);



int cfd=accept(sfd,NULL,NULL);



/* GSS AUTH */



OM_uint32 maj,min;

gss_ctx_id_t ctx=GSS_C_NO_CONTEXT;



gss_buffer_desc in=GSS_C_EMPTY_BUFFER;

gss_buffer_desc out=GSS_C_EMPTY_BUFFER;



do{

    recv_token(cfd,&in);



    maj=gss_accept_sec_context(

        &min,

        &ctx,

        GSS_C_NO_CREDENTIAL,

        &in,

        GSS_C_NO_CHANNEL_BINDINGS,

        NULL,NULL,

        &out,

        NULL,NULL,NULL

    );



    if(out.length>0){

        send_token(cfd,&out);

        gss_release_buffer(&min,&out);

    }



    free(in.value);



}while(maj==GSS_S_CONTINUE_NEEDED);



if(maj!=GSS_S_COMPLETE) die("gss_accept_sec_context");



printf("Authenticated context established.\n");



/* derive key */



unsigned char key[32];

derive_key(ctx,key);



/* receive file */



uint32_t n;

recv_all(cfd,&n,4);

int clen=ntohl(n);



unsigned char nonce[NONCE_LEN];

unsigned char *cipher=malloc(clen);

unsigned char tag[TAG_LEN];



recv_all(cfd,nonce,NONCE_LEN);

recv_all(cfd,cipher,clen);

recv_all(cfd,tag,TAG_LEN);



/* decrypt */



unsigned char *plain=malloc(clen+16);



EVP_CIPHER_CTX *dctx=EVP_CIPHER_CTX_new();



int len=0,plen=0,ret=0;



EVP_DecryptInit_ex(dctx,EVP_aes_256_gcm(),NULL,NULL,NULL);

EVP_CIPHER_CTX_ctrl(dctx,EVP_CTRL_GCM_SET_IVLEN,NONCE_LEN,NULL);

EVP_DecryptInit_ex(dctx,NULL,NULL,key,nonce);



EVP_DecryptUpdate(dctx,plain,&len,cipher,clen);

plen=len;



EVP_CIPHER_CTX_ctrl(dctx,EVP_CTRL_GCM_SET_TAG,TAG_LEN,tag);



ret=EVP_DecryptFinal_ex(dctx,plain+plen,&len);



EVP_CIPHER_CTX_free(dctx);



if(ret<=0){

    printf("TAG VERIFY FAILED\n");

    close(cfd);

    return 1;

}



plen+=len;



FILE *fp=fopen("received.out","wb");

fwrite(plain,1,plen,fp);

fclose(fp);



printf("File received safely.\n");



close(cfd);

close(sfd);

return 0;

}
