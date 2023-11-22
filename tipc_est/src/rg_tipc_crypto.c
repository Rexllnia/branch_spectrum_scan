#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include "rg_tipc_crypto.h"

int file_size(char* filename)
{
    FILE *fp=fopen(filename,"r");
    if(!fp) return -1;
    fseek(fp,0L,SEEK_END);
    int size=ftell(fp);
    fclose(fp);
    
    return size;
}

int write_log_file(char* filename,char *buf)
{
    int ret = 0;
    FILE *log_file;
    log_file = fopen(filename, "a+");
    if (log_file == NULL) {
        perror("TIPC log_file open fail perror");
        return 0;
    }
    ret = fwrite(buf,strlen(buf),1,log_file);
    fclose(log_file);
    log_file = NULL;
    return ret;
}


static const char magic[] = "Salted__";

BIO *bf_init(char *filename, int export)
{
    BIO * bf;
    bf = BIO_new(BIO_s_file());;
    if (bf == NULL) {
        printf("ERROR: BIO_s_file faild.\n");
        return NULL;
    }

    if (filename == NULL) {
        if (export) {
            BIO_set_fp(bf, stdout, BIO_NOCLOSE);
        } else {
            BIO_set_fp(bf, stdin, BIO_NOCLOSE);
        }
    } else {
        if (export) {
            if (BIO_write_filename(bf, filename) <= 0) {
                printf("ERROR: BIO_write_filename faild.\n");
                return NULL;
            }
        } else {
            if (BIO_read_filename(bf, filename) <= 0) {
                printf("ERROR: BIO_read_filename faild.\n");
                return NULL;
            }
        }
    }

    return bf;
}

BIO *b64_init(void)
{
    BIO *b64;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        printf("ERROR: BIO_f_base64 faild.\n");
        return NULL;
    }

    return b64;
}

BIO *b64_dec_init(BIO *btmp, unsigned char *salt)
{
    char mbuf[sizeof(magic) - 1];

    if (btmp == NULL) {
        printf("ERROR: btmp is null in %s on %d lines.\n", __FILE__, __LINE__);
        return NULL;
    }

    if (BIO_read(btmp, mbuf, sizeof(mbuf)) != sizeof(mbuf)) {
        printf("ERROR: BIO_read faild in %s on %d lines.\n", __FILE__, __LINE__);
        return NULL;
    }

    if (BIO_read(btmp, salt, PKCS5_SALT_LEN) != PKCS5_SALT_LEN) {
        printf("ERROR: BIO_read faild in %s on %d lines.\n", __FILE__, __LINE__);
        return NULL;
    }

    if (memcmp(mbuf, magic, sizeof(magic) - 1)) {
        printf("ERROR: bad magic number\n");
        return NULL;
    }

    return btmp;
}

BIO *b64_enc_init(BIO *btmp, unsigned char *salt)
{

    if (btmp == NULL) {
        printf("ERROR: btmp is null in %s on %d lines.\n", __FILE__, __LINE__);
        return NULL;
    }

    if (BIO_write(btmp, magic, sizeof(magic) - 1) != sizeof(magic) - 1) {
        printf("ERROR: BIO_write faild in %s on %d lines.\n", __FILE__, __LINE__);
        return NULL;
    }

    if (BIO_write(btmp, (char *)salt, PKCS5_SALT_LEN) != PKCS5_SALT_LEN) {
        printf("ERROR: BIO_write faild in %s on %d lines.\n", __FILE__, __LINE__);
        return NULL;
    }

    return btmp;
}

void crypto_get_pwd(char *pwd)
{
    char confuse[PWDLEN];

    strcat(pwd, PWDF);
    memset(confuse, 0, PWDLEN);
    strcat(confuse, PWDFALSE1);
    strcat(pwd, PWDS);
    memset(confuse, 0, PWDLEN);
    strcat(confuse, PWDFALSE2);
    strcat(pwd, PWDT);
}

BIO *bcipher_init(char *type, unsigned char *salt, int enc)
{
    BIO *benc;
    const EVP_MD *dgst = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    char pwd[PWDLEN];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char key[EVP_MAX_KEY_LENGTH];

    if (type == NULL || salt == NULL) {
        printf("ERROR: type or salt is null\n");
        return NULL;
    }

    memset(pwd, 0, PWDLEN);
    memset(iv, 0, EVP_MAX_IV_LENGTH);
    memset(key, 0, EVP_MAX_KEY_LENGTH);

    /* reload the encode/decode algorithm */
    OpenSSL_add_all_algorithms();

    dgst = EVP_md5();

    /* get the algorithm */
    cipher = EVP_get_cipherbyname(type);
    crypto_get_pwd(pwd);

    /* generate the coding key and iv */
    EVP_BytesToKey(cipher, dgst, salt, (unsigned char *)pwd, strlen(pwd), 1, key, iv);

    benc = BIO_new(BIO_f_cipher());
    if (benc == NULL) {
        printf("ERROR: type or salt is null\n");
        return NULL;
    }

    BIO_get_cipher_ctx(benc, &ctx);

    /* setting cipher */
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc)) {
        printf("Error setting cipher %s\n", type);
        return NULL;
    }

    return benc;
}

unsigned char *printf_md5_str(unsigned char *md)
{
    int i;
	unsigned char md5_str[MD5_DIGEST_LENGTH*3];
	
    if (md == NULL) {
        return;
    }
    for (i = 0; i < MD5_DIGEST_LENGTH; i++){
        //printf("%02x", md[i]);
		snprintf(md5_str + i*2, 2+1, "%02x", md[i]);
    }
	//printf("md5_str:%s\n",md5_str);
	return md5_str;
}
unsigned char *md5_coding(char *data)
{
    int i;
    MD5_CTX c;
    char pwd[PWDLEN];
    static unsigned char md[MD5_DIGEST_LENGTH+1];
    //static unsigned char buf[BUFSIZE];
	static unsigned char dest_str[512];
    memset(pwd, 0, PWDLEN);
    crypto_get_pwd(pwd);

    /* read string form original_data buf */
    MD5_Init(&c);
    /* add the key before the coding string */
    MD5_Update(&c, (unsigned char *)pwd, strlen(pwd));
	/* add the coding string */
    MD5_Update(&c, data, strlen(data));
    MD5_Final(&(md[0]), &c);	
   	//print_md(md);
	return printf_md5_str(md);
}


int aes_coding(char *inf, char *outf, char *type, int enc)
{
    int inl;
    BIO *b64, *bc, *in, *out, *wb, *rb;
    unsigned char *buff;
    unsigned char salt[PKCS5_SALT_LEN];

    if (type == NULL) {
        printf("Error: crypto coding type is null\n");
        return -1;
    }

    in = bf_init(inf, 0);
    out = bf_init(outf, 1);
    if ((in == NULL) || (out == NULL)) {
        printf("Error: bf_init failed\n");
        return -1;
    }

    rb = in;
    wb = out;

    buff = (unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(BSIZE));
    if (buff == NULL) {
        printf("Error: OPENSSL_malloc failed\n");
        goto end;
    }


    b64 = b64_init();
    if (b64 == NULL) {
        printf("ERROR: b64_init faild.\n");
        goto end;
    }

    memset(salt, 0, PKCS5_SALT_LEN);
    if (enc) {
        wb = BIO_push(b64, wb);

        /* creat salt */
        RAND_bytes(salt, PKCS5_SALT_LEN);
        b64_enc_init(wb, salt);
    } else {
        rb = BIO_push(b64, rb);
        b64_dec_init(rb, salt);
    }

    bc = bcipher_init(type, salt, enc);
    if (bc != NULL) {
        wb = BIO_push(bc, wb);
    } else {
        printf("ERROR: bcipher_init faild.\n");
        goto end;
    }

    /* Only encrypt/decrypt as we write the file */
    for (;;) {
        inl = BIO_read(rb, (char *)buff, BSIZE);
        if (inl <= 0)
            break;
        if (BIO_write(wb, (char *)buff, inl) != inl) {
            printf("ERROR: BIO_write faild in %s on %d lines.\n", __FILE__, __LINE__);
            goto end;
        }
    }

    if (!BIO_flush(wb)) {
        printf("ERROR: bad decrypt\n");
        goto end;
    }

end:
    if (buff != NULL) {
        OPENSSL_free(buff);
    }

    if (in != NULL) {
        BIO_free_all(in);
    }

    if (out != NULL) {
        BIO_free_all(out);
    }

    if (bc != NULL) {
        BIO_free(bc);
    }

    if (b64 != NULL) {
        BIO_free(b64);
    }

    OBJ_cleanup();
    EVP_cleanup();
    RAND_cleanup();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}

