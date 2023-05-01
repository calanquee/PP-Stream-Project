#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gmp.h>
#include "paillier.h"
#include <iostream>
#include "openssl_utils.h"
#include <openssl/sha.h>
#include <sys/time.h>
#include <zmq.h>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include "NumCpp.hpp"


#define Test_Round 1
#define KEY_LEN 512
#define Dimension 28
#define CONV_Thread 13
#define PARTITION_PARA 5

#define image_dimension 28

/* put these definition in globe */
gmp_randstate_t gmp_state;
paillier_pubkey_t *re_paillier_pubkey;
paillier_prvkey_t *re_paillier_privkey;

double tmp_plain_image_data[Dimension*Dimension];
int plain_image_data[Dimension*Dimension];
int plain_image_data_invert[Dimension*Dimension];

/* for encryption */
paillier_plaintext_t *paillier_input;
paillier_ciphertext_t paillier_ciphertext;
paillier_ciphertext_t paillier_ciphertext1;


// image cipher structure
struct image_data{
    paillier_cipher_array paillier_cipher_image[Dimension*Dimension];
}Image;

// partitioned image_1: start/end
struct partition_iamge{
	paillier_cipher_array paillier_cipher_image[Dimension*PARTITION_PARA];
};


// time parameters
struct  timeval starttime;
struct  timeval endtime;
unsigned long int diff;

// zmq parameters
void *afs_context;
void *afs_requester;
int rc;


void afs_init(){
    afs_context = zmq_ctx_new();
    afs_requester = zmq_socket(afs_context, ZMQ_PUSH);
    zmq_connect(afs_requester, "tcp://172.16.112.40:6789");
    assert(rc == 0);
}

void afs_clean(){
    zmq_close(afs_requester);
    zmq_ctx_destroy(afs_context);
}

void analyst_paillier_import_keys(){ /* pub + priv */
	FILE *fpubkey = NULL;
	FILE *fprivkey = NULL;
	if((fpubkey = fopen("../../publicdata/paillier_pub_key.txt", "r+"))==NULL){
		printf("cant open pub key file");
		exit(0);
	}
	if((fprivkey = fopen("../../publicdata/paillier_priv_key.txt", "r+"))==NULL){
		printf("cant open priv key file");
		exit(0);
	}
	char *paillier_pubkey_array = (char *)malloc(sizeof(char)*KEY_LEN*4);
	char *paillier_privkey_array = (char *)malloc(sizeof(char)*KEY_LEN*4);
	/* read key file */
	fread(paillier_pubkey_array,1,KEY_LEN*4,fpubkey);
	fread(paillier_privkey_array,1,KEY_LEN*4,fprivkey);
	/* import paillier keys */
	re_paillier_pubkey = paillier_pubkey_from_hex(paillier_pubkey_array);
	re_paillier_privkey = paillier_prvkey_from_hex(paillier_privkey_array, re_paillier_pubkey);
	/* free file pointer */
	fclose(fpubkey);
	fclose(fprivkey);
	fpubkey = NULL;
	fprivkey = NULL;
	/* free temp array memory */
	free(paillier_pubkey_array);
	free(paillier_privkey_array);
	paillier_pubkey_array = NULL;
	paillier_privkey_array = NULL;
}



long long int paillier_decryption(char *cipherarray,int c_length){
	paillier_ciphertext_t *tmpcipher;
	paillier_plaintext_t output;
	mpz_init(output.m);
	tmpcipher = paillier_ciphertext_from_str(cipherarray,c_length);
	paillier_dec(&output, re_paillier_pubkey, re_paillier_privkey, tmpcipher);
	long long int res = 999; //just for judging output
	if(mpz_get_si(output.m)<pow(10,12) && mpz_get_si(output.m)>(-1)*pow(10,12)){
		res = mpz_get_si(output.m);
		return res;
	}
	else{
		mpz_sub(output.m,output.m,re_paillier_pubkey->n);
		if(mpz_get_si(output.m)<pow(10,12) && mpz_get_si(output.m)>(-1)*pow(10,12)){
			res = mpz_get_si(output.m);
			return res;
		}
	}
}

long long int pailliertext_decryption(paillier_ciphertext_t *tmpcipher){
	paillier_plaintext_t output;
	mpz_init(output.m);
	paillier_dec(&output, re_paillier_pubkey, re_paillier_privkey, tmpcipher);
	long long int res = 999; //just for judging output
	if(mpz_get_si(output.m)<pow(10,12) && mpz_get_si(output.m)>(-1)*pow(10,12)){
		res = mpz_get_si(output.m);
		return res;
	}
	else{
		mpz_sub(output.m,output.m,re_paillier_pubkey->n);
		if(mpz_get_si(output.m)<pow(10,12) && mpz_get_si(output.m)>(-1)*pow(10,12)){
			res = mpz_get_si(output.m);
			return res;
		}
	}
}


void init_cipher_struct(){
	for(int i=0;i<Dimension*Dimension;++i){
		Image.paillier_cipher_image[i].c_length = 0;
		bzero(Image.paillier_cipher_image[i].array, KEY_LEN);
	}
}


int paillier_encryption(long int plaintext,int ordinal){
	mpz_init(paillier_ciphertext.c);
	// printf("init paillier cipher: %d\n",mpz_get_si(paillier_ciphertext.c));
	char *enc_message;
	paillier_input = paillier_plaintext_from_si(plaintext);
	paillier_enc(&paillier_ciphertext, re_paillier_pubkey, paillier_input, &paillier_get_rand_devurandom);
	enc_message = paillier_ciphertext_to_str(&paillier_ciphertext);
	for(int i=0;i<paillier_ciphertext.c_length;++i){
		Image.paillier_cipher_image[ordinal].array[i] = enc_message[i];
	}
	Image.paillier_cipher_image[ordinal].c_length = paillier_ciphertext.c_length;
	free(enc_message);
	enc_message = NULL;
	return 0;
}

int encrypt_image_data(char * filename){
	// read plain data from file
	FILE *fp = NULL;
	fp = fopen(filename, "r+");
	if(fp == NULL){
		printf("Open Falied!");
		return -1;
	}
	double NumberToEnc = 0.0;
	int index = 0;
	while(fscanf(fp, "%lf", &NumberToEnc) != EOF){
		tmp_plain_image_data[index] = (double)NumberToEnc;
        index ++;
		if(index==Dimension*Dimension){
			break;
		}
    }
	fclose(fp);
	fp = NULL;

	for(int i=0;i<Dimension*Dimension;++i){
		tmp_plain_image_data[i] = tmp_plain_image_data[i]*1000.0;
		if(tmp_plain_image_data[i]>=0){
			plain_image_data[i] = (int)(tmp_plain_image_data[i]+0.5);
		}
		else{
			plain_image_data[i] = (int)(tmp_plain_image_data[i]-0.5);
		}
	}

	// invert for FC layer
	int copy_index = 0;
	for(int i=0;i<Dimension;++i){
		for(int j=0;j<Dimension;++j){
			plain_image_data_invert[copy_index] = plain_image_data[j*28+i];
			copy_index ++;
		}
	}


	// encrypt image data
	for(int i=0;i<Dimension*Dimension;++i){
		// printf("%d ", plain_image_data_invert[i]);
		paillier_encryption(plain_image_data[i],i);
	}

}


int main(int argc, char *argv[]){

    // initialize pub keys
	srand(time(NULL));
	analyst_paillier_import_keys();

    // init input array
	init_cipher_struct();
	

	int partition_length = (KEY_LEN+4)*Dimension*PARTITION_PARA;

    // send to AF-Stream
    char image_buffer[410000];
	char sending_buffer[partition_length+1];

	bzero(image_buffer, 410000);
	bzero(sending_buffer, partition_length+1);

    encrypt_image_data((char *)"image.txt");
	memcpy(image_buffer, &Image, sizeof(Image));


	// communication initialization
    afs_init();

	for(int round=0;round<Test_Round;++round){
		for(int index=0;index<CONV_Thread;++index){
			if(index==0){
				for(int i=0;i<partition_length;++i){
					sending_buffer[i] = image_buffer[i];
				}
			}
			else{
				for(int i=0;i<partition_length;++i){
					sending_buffer[i] = image_buffer[(2*index-1)*Dimension*(KEY_LEN+4)+i];
				}
			}
			// memcpy(&partition_iamges[index], sending_buffer, sizeof(partition_iamges[index]));
			sending_buffer[partition_length] = index + 1;
			zmq_send(afs_requester, sending_buffer, partition_length+1, 0);
			bzero(sending_buffer, partition_length+1);
			// printf("index = %d\n", index);
		}
    }


	gettimeofday(&starttime, NULL);
    printf("%ld %ld\n", starttime.tv_sec, starttime.tv_usec);

    // close connection
    afs_clean();

    return 0;
}