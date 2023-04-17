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

class MergeThread : public afs::ComputeThread<struct ReLUItem, struct VectorItem, afs::NullClass, afs::NullClass> {
public:
    MergeThread(int num_upstreams, int num_downstream) :
        afs::ComputeThread<struct ReLUItem, struct VectorItem, afs::NullClass, afs::NullClass>(num_upstreams, num_downstream) {}


private:
    // paillier parameters
    long long int value;
    paillier_cipher_array* res_to_merge;

    // load fc para
    double tmp_fc_parameter_3[100*10];
    int convert_fc_parameter_3[100*10];
    int fc_para_array_3[10][100];
    
    // time parameters
    struct timeval Endtime;
    int time_index;
    struct  timeval starttime[128*10];
    struct  timeval endtime[128*10];
    unsigned long long int diff;

    // paillier keys
    paillier_pubkey_t *paillier_pubkey;
    paillier_prvkey_t *paillier_privkey;

    // for fc3 func
    paillier_plaintext_t* pt;
    paillier_ciphertext_t* paillier_ciphertext_res;

    // for ob
    int true_permutation_index[100];
    int random_seed = 2;

    
    char relu_result[845*516];

    // relu2_result
    struct relu_data{
        paillier_cipher_array relu[845];
    }RELU;
    paillier_ciphertext_t* ciphertext_relu[100];

    void init_paillier_ciphertext(paillier_ciphertext_t* ct){
        mpz_init(ct->c);
        ct->c_length = 0;
    }

    void init_paillier_cipher_array(paillier_cipher_array* paillier_cipherarray){
        bzero(paillier_cipherarray->array, KEY_LEN);
        paillier_cipherarray->c_length = 0;
    }
    
    void init_cipher_struct(){
        for(int i=0;i<100;++i){
            RELU.relu[i].c_length = 0;
            bzero(RELU.relu[i].array, KEY_LEN);
        }
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

    paillier_cipher_array* array_paillier_encryption(long long int plaintext){
        paillier_ciphertext_t paillier_ciphertext; /* for temp cipher */
        mpz_init(paillier_ciphertext.c);
        paillier_cipher_array* encryption_result;
        encryption_result = (paillier_cipher_array*)malloc(sizeof(paillier_cipher_array));
        //	printf("init paillier cipher: %d\n",mpz_get_si(paillier_ciphertext.c));
	    char *enc_message;
        paillier_plaintext_t *paillier_input;
        paillier_input = paillier_plaintext_from_si(plaintext);
        paillier_enc(&paillier_ciphertext, paillier_pubkey, paillier_input, &paillier_get_rand_devurandom);
        enc_message = paillier_ciphertext_to_str(&paillier_ciphertext);
        encryption_result->c_length = paillier_ciphertext.c_length;
        for(int i=0;i<encryption_result->c_length;++i){
            encryption_result->array[i] = enc_message[i];
        }
        free(enc_message);
        enc_message = NULL;
        return encryption_result;
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

    void InvrandpermC(int seed, int N, int* result){       
        int *arr = (int*)malloc(N*sizeof(int));
        int *tmp = (int*)malloc(N*sizeof(int));
        int count = 0;
        memset(arr,0,N*sizeof(int));
        srand(seed);
        while(count<N){
            int val = rand()%N;
            if(!arr[val]){
                // printf("%d ",val);
                tmp[count] = val;
                arr[val]=1;
                ++count;
            }
        }
        for(int i=0;i<N;++i){
            result[tmp[i]] = i;
        }
        free(arr);
        free(tmp);
        arr = NULL;
        tmp = NULL;
    }


    void randpermC(int seed, int N, int* result){       
        int *arr = (int*)malloc(N*sizeof(int)); 
        int count = 0;
        memset(arr,0,N*sizeof(int));
        srand(seed);
        while(count<N){
            int val = rand()%N;
            if(!arr[val]){
                // printf("%d ",val);
                result[count] = val;
                arr[val]=1;
                ++count;
            }
        }
        free(arr);
        arr = NULL;
    }

    void compute_fc3(int index, paillier_cipher_array* encryption_result){
        // fc1
        paillier_ciphertext_t* ciphertext_fc1_output = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        ciphertext_fc1_output = paillier_encryption(0);
        // compute fc1
        for(int j=0;j<100;++j){
            mpz_init_set_si(pt->m, fc_para_array_3[index][j]);
            paillier_mul(paillier_pubkey, paillier_ciphertext_res, ciphertext_relu[j], pt);
            paillier_add(paillier_pubkey, ciphertext_fc1_output, ciphertext_fc1_output, paillier_ciphertext_res);
        }
        char *enc_message;
        enc_message = paillier_ciphertext_to_str(ciphertext_fc1_output);
        encryption_result->c_length = ciphertext_fc1_output->c_length;
        for(int i=0;i<encryption_result->c_length;++i){
            encryption_result->array[i] = enc_message[i];
        }
        free(enc_message);
        enc_message = NULL;
        // free memory
        // paillier_freeciphertext(paillier_ciphertext_res);
        paillier_freeciphertext(ciphertext_fc1_output);
        // paillier_freeplaintext(pt);
        // paillier_ciphertext_res = NULL;
        ciphertext_fc1_output = NULL;
        // pt = NULL;
    }

    void FCParaInit(Config* config){
        int scaling_factor = config->getint("scaling_factor", 0);
        if(scaling_factor == 0){
            printf("No scaling_factor!\n");
        }
        FILE* fc_para_fp = NULL;
        char* fc_para_file = config->getstring("fc_para_file", NULL);
        fc_para_fp = fopen(fc_para_file, "r");
        if(fc_para_fp == NULL){
            printf("can't open fc para file!\n");
        }
        double NumberFromFile = 0.0;
        int index = 0;
        while(fscanf(fc_para_fp, "%lf", &NumberFromFile) != EOF){
            tmp_fc_parameter_3[index] = NumberFromFile;
            index ++;
            if(index==100*10){
                break;
            }
        }
        fclose(fc_para_fp);
        fc_para_fp = NULL;

        // convert double to int: *scaling_factor
        for(int i=0;i<100*10;++i){
            tmp_fc_parameter_3[i] = tmp_fc_parameter_3[i]*pow(10,scaling_factor);
            convert_fc_parameter_3[i] = (int)(tmp_fc_parameter_3[i]);
        }

        // put fc para into 128 arrays
        for(int i=0;i<10;++i){
            for(int j=0;j<100;++j){
                fc_para_array_3[i][j] = convert_fc_parameter_3[i*100+j];
            }
        }
    }

    void ComputeThreadInit() {
        Config* config = Config::getInstance();

        // load fc3 para
        FCParaInit(config);

        // init keys
        collector_paillier_import_keys();

        // for decryption test
        value = 0;
        
        // init cipher context
        res_to_merge = (paillier_cipher_array*)malloc(sizeof(paillier_cipher_array));
        init_paillier_cipher_array(res_to_merge);
        for(int i=0;i<100;++i){
            ciphertext_relu[i] = (paillier_ciphertext_t*)malloc(sizeof(paillier_ciphertext_t));
            init_paillier_ciphertext(ciphertext_relu[i]);
        }
        
        // for fc3 func
        pt = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
        paillier_ciphertext_res = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        mpz_init(paillier_ciphertext_res->c);

        time_index = 0;
        diff = 0;
    }

    void TerminateWindow1(char *ciphertext, int length, int i_index) {
        VectorItem* cm_item = new VectorItem;
        cm_item->AppendCipher(ciphertext, length);
        cm_item->AppendCellIndex(i_index);
        EmitData(0, *cm_item);
        // just for test
        /*
        value = paillier_decryption(ciphertext, length);
        printf("%d value = %lld\n", i_index, value);
        */
        delete cm_item;
    }


    void ComputeThreadFinish(){ // free memory and close connection
        gettimeofday(&Endtime, NULL);
        printf("%lld %lld\n", Endtime.tv_sec, Endtime.tv_usec);
        // zmq_send(requester, send_buffer, 1, 0);
        // close_zmq_connect();
        for(int i=0;i<time_index;++i){
            diff = diff + 1000000 * (endtime[i].tv_sec-starttime[i].tv_sec)+ (long long)endtime[i].tv_usec-(long long)starttime[i].tv_usec;
            // LOG_MSG("Latency: %lld\n",diff);
        }
        printf("merge_time: %lld\n", diff);
    }

    void ComputeThreadRecovery() {}

    void ProcessData(uint32_t worker, uint32_t thread, uint64_t seq, struct ReLUItem &item) {
        InvrandpermC(random_seed, 100, true_permutation_index);
        int cellindex = item.cell_index;
        // printf("%d %ld\n", cellindex, pthread_self());
        for(int i=0;i<845*516;++i){
            relu_result[i] = item.relu_result_buf[i];
        }
        memcpy(&RELU, relu_result, sizeof(RELU));
        for(int i=0;i<100;++i){
            formal_paillier_ciphertext_from_str(RELU.relu[i].array, RELU.relu[i].c_length, ciphertext_relu[true_permutation_index[i]]);
        }
        bzero(relu_result, 845*516);
        for(int i=0;i<10;++i){
            compute_fc3(cellindex*10+i, res_to_merge);
            TerminateWindow1(res_to_merge->array, res_to_merge->c_length, cellindex*10+i);
        }
    }

    void ProcessPunc() {}

};
