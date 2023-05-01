#include <string>
#include <unordered_map>
#include <random>
#include <sstream>
#include <set>
#include <afstream.h>
#include "test_item.hpp"
#include "relu_item.hpp"
#include "paillier_structure.h"
#include <sys/time.h>
#include <time.h>
#include <math.h>

#define KEY_LEN 512

// Note: current implementation does not support sync at the end of window.
// Please guarantee that there is only one window in the input

class MergeThread : public afs::ComputeThread<struct VectorItem, struct VectorItem, afs::NullClass, afs::NullClass> {
public:
    MergeThread(int num_upstreams, int num_downstream) :
        afs::ComputeThread<struct VectorItem, struct VectorItem, afs::NullClass, afs::NullClass>(num_upstreams, num_downstream) {}


private:
    // paillier parameters
    long long int value;
    char process_array_cipher[KEY_LEN];

    int merge_count;
    int max_index;
    long long int max_result; 

    
    // time parameters
    struct timeval Endtime;
    int time_index;
    struct  timeval starttime[128*10];
    struct  timeval endtime[128*10];
    unsigned long long int diff;

    void init_paillier_ciphertext(paillier_ciphertext_t* ct){
        mpz_init(ct->c);
        ct->c_length = 0;
    }

    void init_paillier_cipher_array(paillier_cipher_array* paillier_cipherarray){
        bzero(paillier_cipherarray->array, KEY_LEN);
        paillier_cipherarray->c_length = 0;
    }
    
    void collector_paillier_import_keys(){ /* pub + priv */
        FILE *fpubkey = NULL;
        FILE *fprivkey = NULL;
        if((fpubkey = fopen("../../../../publicdata/paillier_pub_key.txt", "r+"))==NULL){
            printf("cant open pub key file");
            exit(0);
        }
        if((fprivkey = fopen("../../../../publicdata/paillier_priv_key.txt", "r+"))==NULL){
            printf("cant open priv key file");
            exit(0);
        }
        char *paillier_pubkey_array = (char *)malloc(sizeof(char)*KEY_LEN*4);
        char *paillier_privkey_array = (char *)malloc(sizeof(char)*KEY_LEN*4);
        /* read key file */
        fread(paillier_pubkey_array,1,KEY_LEN*4,fpubkey);
        fread(paillier_privkey_array,1,KEY_LEN*4,fprivkey);
        /* import paillier keys */
        paillier_pubkey = paillier_pubkey_from_hex(paillier_pubkey_array);
        paillier_privkey = paillier_prvkey_from_hex(paillier_privkey_array, paillier_pubkey);
        // test n
        // mpz_t test_n = *paillier_pubkey->n;
        // printf("n=%llu\n", test_n);
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

    paillier_ciphertext_t* paillier_encryption(long long int plaintext){
        paillier_ciphertext_t *paillier_ciphertext = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        mpz_init(paillier_ciphertext->c);
        paillier_ciphertext->c_length = 0;
        paillier_plaintext_t *paillier_input;
        paillier_input = paillier_plaintext_from_si(plaintext);
        paillier_enc(paillier_ciphertext, paillier_pubkey, paillier_input, &paillier_get_rand_devurandom);
        return paillier_ciphertext;
    }


    long long int paillier_decryption(char *cipherarray,int c_length){
	    paillier_ciphertext_t *tmpcipher;
        paillier_plaintext_t output;
        mpz_init(output.m);
        tmpcipher = paillier_ciphertext_from_str(cipherarray,c_length);
        paillier_dec(&output, paillier_pubkey, paillier_privkey, tmpcipher);
	    long long int res = 999; //just for judging output
        if(mpz_get_si(output.m)<pow(10,11) && mpz_get_si(output.m)>(-1)*pow(10,11)){
            res = mpz_get_si(output.m);
            return res;
        }
        else{
            mpz_sub(output.m,output.m,paillier_pubkey->n);
            if(mpz_get_si(output.m)<pow(10,11) && mpz_get_si(output.m)>(-1)*pow(10,11)){
                res = mpz_get_si(output.m);
                return res;
            }
        }
    }

    long long int pailliertext_decryption(paillier_ciphertext_t *tmpcipher){
        paillier_plaintext_t output;
        mpz_init(output.m);
        paillier_dec(&output, paillier_pubkey, paillier_privkey, tmpcipher);
        long long int res = 999; //just for judging output
        if(mpz_get_si(output.m)<pow(10,11) && mpz_get_si(output.m)>(-1)*pow(10,11)){
            res = mpz_get_si(output.m);
            return res;
        }
        else{
            mpz_sub(output.m,output.m,paillier_pubkey->n);
            if(mpz_get_si(output.m)<pow(10,11) && mpz_get_si(output.m)>(-1)*pow(10,11)){
                res = mpz_get_si(output.m);
                return res;
            }
        }
    }


    void ComputeThreadInit() {
        Config* config = Config::getInstance();

        // init keys
        collector_paillier_import_keys();

        // for softmax
        value = 0;
        max_index = -1;
        max_result = -1;
        merge_count = 0;
        
        time_index = 0;
        diff = 0;
    }


    void ComputeThreadFinish(){ // free memory and close connection
        // printf("inference_result = %d\n", max_index);
        gettimeofday(&Endtime, NULL);
        printf("%lld %lld\n", Endtime.tv_sec, Endtime.tv_usec);
    }


    void ComputeThreadRecovery() {}

    void ProcessData(uint32_t worker, uint32_t thread, uint64_t seq, struct VectorItem &item) {
        int cellindex = item.cell_index;
        int process_cipher_length = item.cipher_length;
        bzero(process_array_cipher, KEY_LEN);
        for(int i=0;i<process_cipher_length;++i){
            process_array_cipher[i] = item.cipher_array[i];
        }
        value = paillier_decryption(process_array_cipher, process_cipher_length);
        printf("%d process value = %lld\n", cellindex, value);
        if(max_result<value){
            max_result = value;
            max_index = cellindex;
        }
        merge_count ++;
        if(merge_count==10){
            printf("inference result: %d\n", max_index);
            ComputeThreadFinish();
            merge_count = 0;
            max_result = -1;
            max_index = -1;

        }
    }

    void ProcessPunc() {}

};
