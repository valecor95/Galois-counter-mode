#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/modes.h>

#define CBC 0
#define GCM 1
#define AES_BLOCK_SIZE 16

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

void enc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, int mode, unsigned char *tag){
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;
    int iv_len = strlen((char*) iv);
    //int aad;
    //unsigned char* aad;

    //Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(mode == CBC){
        //Initialise the encryption operation.
  		  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
        //Provide the message to be encrypted, and obtain the encrypted output. EVP_EncryptUpdate can be called multiple times if necessary
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){ handleErrors();} ciphertext_len = len;
        //Finalise the encryption. Further ciphertext bytes may be written at this stage.
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){ handleErrors();} ciphertext_len += len;
    }
    if(mode == GCM){
        //Initialise the encryption operation. IMPORTANT - ensure you use a key and IV size appropriate for your cipher
  		  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
        //Set IV length if default 12 bytes (96 bits) is not appropriat
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) handleErrors();
        //Initialise key and IV
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
        //Provide any AAD data. This can be called zero or more times as required
        //if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();
        //Provide the message to be encrypted, and obtain the encrypted output. EVP_EncryptUpdate can be called multiple times if necessary
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){ handleErrors();} ciphertext_len = len;
        //Finalise the encryption. Normally ciphertext bytes may be written at this stage, but this does not occur in GCM mode
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){ handleErrors();} ciphertext_len += len;
        //Get the tag
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handleErrors();
    }

    //Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void dec(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int mode, unsigned char *tag){
    EVP_CIPHER_CTX *ctx;

    int len, plaintext_len, ret;
    int iv_len = 16;
    //int aad;
    //unsigned char* aad;

    //Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(mode == CBC){
        //Initialise the decryption operation.
    		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
        //Provide the message to be decrypted, and obtain the plaintext output. EVP_DecryptUpdate can be called multiple times if necessary.
        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){ handleErrors();} plaintext_len = len;
        //Finalise the decryption. Further plaintext bytes may be written at this stage.
        if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){ handleErrors();} plaintext_len += len;
    }
    if(mode == GCM){
        //Initialise the decryption operation
    		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
        //Set IV length. Not necessary if this is 12 bytes (96 bits)
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) handleErrors();
        //Initialise key and IV
        if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();
        //Provide any AAD data. This can be called zero or more times as required
        //if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();
        //Provide the message to be decrypted, and obtain the plaintext output. EVP_DecryptUpdate can be called multiple times if necessary
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){ handleErrors();} plaintext_len = len;
        //Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) handleErrors();
        //Finalise the decryption. A positive return value indicates success, anything else is a failure - the plaintext is not trustworthy.
        ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        if(ret > 0) plaintext_len += len;     //Success
        else printf("Decryption failed\n");     //Failed
    }

    //Clean up
    EVP_CIPHER_CTX_free(ctx);
}


int main (int argc, char **argv)
{
  if(argc < 2){
    printf("Usage ./galois_counter_mode filename");
    exit(1);
  }

	/* Message to be encrypted */
	/*****************************************************************************************************************************/
	unsigned char* in;													// Structure for input file
  unsigned char* tmp;													// Structure for input file
	unsigned long in_size;
	// in  <-  file in input
	printf("*** READING FILE ***\n");

	char* filename = argv[1];

	int fd = open(filename, O_RDONLY, (mode_t)0666);
	int fdr = fd;
	if(fd == -1) fprintf(stderr, "Error in open file\n");
	in_size = lseek(fd, 0, SEEK_END);
	in = malloc(sizeof(char)*in_size);
	in = (unsigned char*) mmap(0, in_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fdr, 0);
	close(fdr);

	printf("Length of file = %ld Bytes\n", in_size);
	printf("*** END READING FILE ***\n\n");
	/*****************************************************************************************************************************/

  unsigned char* key_256 = malloc(sizeof(char)*32);
	unsigned char* iv_128 = malloc(sizeof(char)*16);
  unsigned char tag[16];
	unsigned char* aux_iv_128 = malloc(sizeof(char)*16);
	clock_t start, end;																				                     // clock for timing
	double enc_time = 0, dec_time = 0;


	printf("********************************************* Cipher Algorithm: AES *********************************************\n\n");
	RAND_bytes(key_256, 32);
	RAND_bytes(iv_128, 16);

  int cipher_len = in_size;
  unsigned char* ciphertext = malloc((sizeof(char)*cipher_len));
  int palaintext_len = cipher_len;
  unsigned char* plaintext = malloc((sizeof(char)*palaintext_len));

	printf("	+++++++++++++++++++++ Operative Mode: GCM\n");
	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	enc(in, in_size, key_256, aux_iv_128, ciphertext, GCM, tag);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);

	printf("	DECRYPTING");
	start = clock();
	dec(ciphertext, cipher_len, key_256, iv_128, plaintext, GCM, tag);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_time/dec_time));

  //printf("Ciphertext is:\n");
  //BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
  //printf("plaintext is:\n");
  //BIO_dump_fp (stdout, (const char *)plaintext, cipher_len);

  int enc_out_size = ((in_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	unsigned char* enc_out = malloc((sizeof(char)*enc_out_size));									// Structure for encryption output
	int dec_out_size = enc_out_size;
	unsigned char* dec_out = malloc((sizeof(char)*dec_out_size));									// Structure for decryption output

  printf("	+++++++++++++++++++++ Operative Mode: CBC\n");
	printf("	ENCRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	enc(in, in_size, key_256, aux_iv_128, enc_out, CBC, NULL);
	end = clock();
	enc_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", enc_time);

	printf("	DECRYPTING");
	memcpy(aux_iv_128, iv_128, AES_BLOCK_SIZE);
	start = clock();
	dec(enc_out, enc_out_size, key_256, aux_iv_128, dec_out, CBC, NULL);
	end = clock();
	dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);
	printf("	SPEED RATIO ==========> %lf\n\n", (enc_time/dec_time));

  //printf("Ciphertext is:\n");
  //BIO_dump_fp (stdout, (const char *)enc_out, enc_out_size);
  //printf("plaintext is:\n");
  //BIO_dump_fp (stdout, (const char *)dec_out, enc_out_size);

  free(enc_out);
	free(dec_out);
  free(ciphertext);
  free(plaintext);
  free(key_256);
	free(iv_128);
  free(aux_iv_128);

  return 0;
}
