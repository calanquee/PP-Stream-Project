#include <string>
#include <unordered_map>
#include <random>
#include <sstream>
#include <set>
#include <afstream.h>
#include "test_item.hpp"
#include "relu_item.hpp"
// #include "paillier_structure.h"
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
    
    // for sending to downstream worker
    paillier_cipher_array* res_to_merge;

    // for syn
    char image_for_process_index;

    int relu_decrease_scale;
    int merge_count;

    // paillier keys
    paillier_pubkey_t *paillier_pubkey;
    paillier_prvkey_t *paillier_privkey;


    struct relu_data{
        paillier_cipher_array relu[128];
    }RELU;

    char relu_result[128*516];
    int relu_index;
    
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
        char *paillier_pubkey_array = (char *)malloc(sizeof(char)*KEY_LEN);
        char *paillier_privkey_array = (char *)malloc(sizeof(char)*KEY_LEN);
        /* read key file */
        fread(paillier_pubkey_array,1,KEY_LEN,fpubkey);
        fread(paillier_privkey_array,1,KEY_LEN,fprivkey);
        /* import paillier keys */
        paillier_pubkey = paillier_pubkey_from_hex(paillier_pubkey_array);
        paillier_privkey = paillier_prvkey_from_hex(paillier_privkey_array, paillier_pubkey);
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
    
    void array_paillier_encryption(int index, long long int plaintext){
        paillier_ciphertext_t* paillier_ciphertext = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        mpz_init(paillier_ciphertext->c);
        //	printf("init paillier cipher: %d\n",mpz_get_si(paillier_ciphertext.c));
	    char *enc_message;
        paillier_plaintext_t *paillier_input;
        paillier_input = paillier_plaintext_from_si(plaintext);
        paillier_enc(paillier_ciphertext, paillier_pubkey, paillier_input, &paillier_get_rand_devurandom);
        enc_message = paillier_ciphertext_to_str(paillier_ciphertext);
        RELU.relu[index].c_length = paillier_ciphertext->c_length;
        for(int i=0;i<paillier_ciphertext->c_length;++i){
            RELU.relu[index].array[i] = enc_message[i];
        }
        free(enc_message);
        paillier_freeciphertext(paillier_ciphertext);
        enc_message = NULL;
        paillier_ciphertext = NULL;
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

    void generate_relu_pailliercipher(long long int relu_value, paillier_cipher_array* encryption_result){
        paillier_ciphertext_t *paillier_ciphertext = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        mpz_init(paillier_ciphertext->c);
        paillier_ciphertext->c_length = 0;
        paillier_plaintext_t *paillier_input;
        paillier_input = paillier_plaintext_from_si(relu_value);
        paillier_enc(paillier_ciphertext, paillier_pubkey, paillier_input, &paillier_get_rand_devurandom);
        char *enc_message;
        enc_message = paillier_ciphertext_to_str(paillier_ciphertext);
        encryption_result->c_length = paillier_ciphertext->c_length;
        for(int i=0;i<encryption_result->c_length;++i){
            encryption_result->array[i] = enc_message[i];
        }
        free(enc_message);
        enc_message = NULL;
        paillier_freeciphertext(paillier_ciphertext);
        paillier_ciphertext = NULL;
    }


    long long int paillier_decryption(char *cipherarray,int c_length){
	    paillier_ciphertext_t *tmpcipher;
        paillier_plaintext_t output;
        mpz_init(output.m);
        tmpcipher = paillier_ciphertext_from_str(cipherarray,c_length);
        paillier_dec(&output, paillier_pubkey, paillier_privkey, tmpcipher);
	    long long int res = 999; //just for judging output
        if(mpz_get_si(output.m)<pow(10,18) && mpz_get_si(output.m)>(-1)*pow(10,18)){
            res = mpz_get_si(output.m);
            return res;
        }
        else{
            mpz_sub(output.m,output.m,paillier_pubkey->n);
            if(mpz_get_si(output.m)<pow(10,18) && mpz_get_si(output.m)>(-1)*pow(10,18)){
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
        if(mpz_get_si(output.m)<pow(10,18) && mpz_get_si(output.m)>(-1)*pow(10,18)){
            res = mpz_get_si(output.m);
            return res;
        }
        else{
            mpz_sub(output.m,output.m,paillier_pubkey->n);
            if(mpz_get_si(output.m)<pow(10,18) && mpz_get_si(output.m)>(-1)*pow(10,18)){
                res = mpz_get_si(output.m);
                return res;
            }
        }
    }


    void ComputeThreadInit() {
        Config* config = Config::getInstance();
        int scaling_factor = config->getint("scaling_factor", 0);
        if(scaling_factor == 0){
            printf("No scaling_factor!\n");
        }
        relu_index = config->getint("relu_index", 0);
        if(relu_index == 0){
            printf("No relu_index!\n");
        }
        if(relu_index==1){
            relu_decrease_scale = 3*scaling_factor-2;
        }
        else{
            relu_decrease_scale = 3*scaling_factor;
        }
        

        // for decryption test
        value = 0;

        // for syn
        image_for_process_index = 0;
        
        // init keys
        collector_paillier_import_keys();

        // init cipher context
        res_to_merge = (paillier_cipher_array*)malloc(sizeof(paillier_cipher_array));
        init_paillier_cipher_array(res_to_merge);

        // init cipher context for fc2
        for(int i=0;i<128;++i){
            RELU.relu[i].c_length = 0;
            bzero(RELU.relu[i].array, KEY_LEN);
        }
        bzero(relu_result, 128*516);

        time_index = 0;
        diff = 0;
        merge_count = 0;
    }


    void TerminateWindow1(char *ciphertext, int length, int i_index, char image_process_index) {
        VectorItem* cm_item = new VectorItem;
        cm_item->AppendCipher(ciphertext, length);
        cm_item->AppendCellIndex(i_index);
        cm_item->AppendImageIndex(image_process_index);
        // printf("image_index=%d\n",image_process_index);
        EmitData(0, *cm_item);
        // value = paillier_decryption(ciphertext, length);
        // printf("value %d %lld\n", i_index, value);
        delete cm_item;
    }
    


    void ComputeThreadFinish(){ // free memory and close connection
        gettimeofday(&Endtime, NULL);
        printf("%lld %lld\n", Endtime.tv_sec, Endtime.tv_usec);
        for(int i=0;i<time_index;++i){
            diff = diff + 1000000 * (endtime[i].tv_sec-starttime[i].tv_sec)+ (long long)endtime[i].tv_usec-(long long)starttime[i].tv_usec;
            // LOG_MSG("Latency: %lld\n",diff);
        }
        printf("merge_time: %lld\n", diff);
    }

    void ComputeThreadRecovery() {}

    void ProcessData(uint32_t worker, uint32_t thread, uint64_t seq, struct VectorItem &item) {
        int cellindex = item.cell_index;
        // gettimeofday(&starttime[time_index],NULL);
        int process_cipher_length = item.cipher_length;
        image_for_process_index = item.image_index;
        bzero(process_array_cipher, KEY_LEN);
        for(int i=0;i<process_cipher_length;++i){
            process_array_cipher[i] = item.cipher_array[i];
        }
        // gettimeofday(&starttime[time_index],NULL);
        value = paillier_decryption(process_array_cipher, process_cipher_length);
        if(value > 0){
            value = value/pow(10,relu_decrease_scale);
        }
        else{
            value = 0;
        }
        generate_relu_pailliercipher(value, res_to_merge);
        TerminateWindow1(res_to_merge->array, res_to_merge->c_length, cellindex, image_for_process_index);
        init_paillier_cipher_array(res_to_merge);
    }

    void ProcessPunc() {}

};
