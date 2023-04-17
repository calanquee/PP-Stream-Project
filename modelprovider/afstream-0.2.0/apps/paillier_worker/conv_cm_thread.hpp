#include <string>
#include <unordered_map>
#include <random>
#include <sstream>
#include <afstream.h>
#include <set>
#include <math.h>
#include "NumCpp.hpp"
#include "test_item.hpp"
#include "paillier.h"
// #include "paillier_structure.h"
// #include "cm_sketch.hpp"

#include <sys/time.h>
#include <time.h>

#define KEY_LEN 512

//#include "operator/hashmap_l1norm.hpp"
//#include "operator/count_min.hpp"

class ComputeThreadThread : public afs::ComputeThread<afs::RawItem,  struct VectorItem, afs::NullClass, afs::NullClass> {
public:
    ComputeThreadThread(int num_downstream) :
        afs::ComputeThread<afs::RawItem,  struct VectorItem, afs::NullClass, afs::NullClass>(0, num_downstream) {}

private:
    paillier_cipher_array* res_to_merge;

    // paillier keys
    // private keys for test
    paillier_pubkey_t *re_paillier_pubkey;
    paillier_prvkey_t *re_paillier_privkey;
    paillier_pubkey_t *paillier_pubkey;
    paillier_prvkey_t *paillier_privkey;

    // for conv1+bn1 func
    paillier_plaintext_t* pt[5*25];
    paillier_ciphertext_t* paillier_ciphertext_res;
    paillier_plaintext_t* varbn[5];
    paillier_plaintext_t* scalebn[5];
    
    // load conv para
    double tmp_conv_parameter_1[25*5];
    int convert_conv_parameter_1[25*5];
    // int conv_para_array_1[5][25];
    long long int value;
    int image_index = 0;
    int conv_instructor[25][169];

    // for syn
    char image_for_process_index;
    
    // for ob
    int random_seed;
    int random_permutation_index[845];
    int ob_index;

    // load bn parameters
    long double tmp_bn1_mean[5];
    double tmp_bn1_var[5];
    double tmp_bn1_scale[5];
    long long int bn1_mean[5];
    long long int bn1_var[5];
    long long int bn1_scale[5];
    paillier_ciphertext_t* ciphertext_bn1_mean[5];
    
    // time parameters
    int time_index;
    struct  timeval starttime[128*10];
    struct  timeval endtime[128*10];
    unsigned long long int diff;
    
    // image cipher structure
    struct image_data{
        paillier_cipher_array paillier_cipher_image[28*28];
    }Image;

    // image ciphertext
    paillier_ciphertext_t* ciphertext_image[28*28];

    
    // init res-to-merge
    void init_paillier_cipher_array(paillier_cipher_array* paillier_cipherarray){
        bzero(paillier_cipherarray->array, KEY_LEN);
        paillier_cipherarray->c_length = 0;
    }

    void init_paillier_ciphertext(paillier_ciphertext_t* ct){
        mpz_init(ct->c);
        ct->c_length = 0;
    }

    void init_cipher_struct(){
        for(int i=0;i<28*28;++i){
            Image.paillier_cipher_image[i].c_length = 0;
            bzero(Image.paillier_cipher_image[i].array, KEY_LEN);
        }
    }


    void sp_paillier_import_pubkey(){ /* pub only */
        FILE *fpubkey = NULL;
        if((fpubkey = fopen("../../../../publicdata/paillier_pub_key.txt", "r+"))==NULL){
            printf("cant open pub key file");
            exit(0);
        }
        char *paillier_pubkey_array = (char *)malloc(sizeof(char)*KEY_LEN);
        bzero(paillier_pubkey_array, KEY_LEN);
        /* read key file */
        fread(paillier_pubkey_array,1,KEY_LEN,fpubkey);
        /* import paillier keys */
        re_paillier_pubkey = paillier_pubkey_from_hex(paillier_pubkey_array);
        /* free file pointer */
        fclose(fpubkey);
        fpubkey = NULL;
        /* free temp array memory */
        free(paillier_pubkey_array);
        paillier_pubkey_array = NULL;
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

    void BNParaInit(Config* config){
        int scaling_factor = config->getint("scaling_factor", 0);
        if(scaling_factor == 0){
            printf("No scaling_factor!\n");
        }
        FILE* bn1_mean_fp = NULL;
        FILE* bn1_var_fp = NULL;
        FILE* bn1_scale_fp = NULL;
        char* bn1_mean_file = config->getstring("bn1_mean_file", NULL);
        char* bn1_var_file = config->getstring("bn1_var_file", NULL);
        char* bn1_scale_file = config->getstring("bn1_scale_file", NULL);
        bn1_mean_fp = fopen(bn1_mean_file, "r");
        bn1_var_fp = fopen(bn1_var_file, "r");
        bn1_scale_fp = fopen(bn1_scale_file, "r");
        if(bn1_mean_fp == NULL || bn1_var_fp == NULL || bn1_scale_fp == NULL){
            printf("can't open bn para file!\n");
        }
        double NumberFromFile = 0.0;
        int index = 0;
        int countindex = 0;
        char temp[200];
        while(!feof(bn1_mean_fp)){
            while(index<4){
                fgets(temp, 200, bn1_mean_fp);
                index ++;
            }
            index = 0;
            fscanf(bn1_mean_fp, "%lf", &NumberFromFile);
            tmp_bn1_mean[countindex] = NumberFromFile;
            countindex ++;
        }
        countindex = 0;
        while(!feof(bn1_var_fp)){
            while(index<4){
                fgets(temp, 200, bn1_var_fp);
                index ++;
            }
            index = 0;
            fscanf(bn1_var_fp, "%lf", &NumberFromFile);
            tmp_bn1_var[countindex] = NumberFromFile;
            countindex ++;
        }
        countindex = 0;
        while(!feof(bn1_scale_fp)){
            while(index<4){
                fgets(temp, 200, bn1_scale_fp);
                index ++;
            }
            index = 0;
            fscanf(bn1_scale_fp, "%lf", &NumberFromFile);
            tmp_bn1_scale[countindex] = NumberFromFile;
            countindex ++;
        }
        fclose(bn1_mean_fp);
        fclose(bn1_var_fp);
        fclose(bn1_scale_fp);
        bn1_mean_fp = NULL;
        bn1_var_fp = NULL;
        bn1_scale_fp = NULL;

        // convert bn parameters to int
        for(int i=0;i<5;++i){
            tmp_bn1_mean[i] = (-1)*tmp_bn1_mean[i]*pow(10,scaling_factor+3);
            bn1_mean[i] = (long long int)(tmp_bn1_mean[i]);
        }
        for(int i=0;i<5;++i){
            tmp_bn1_scale[i] = tmp_bn1_scale[i]*pow(10,scaling_factor);
            bn1_scale[i] = (long long int)(tmp_bn1_scale[i]);

        }
        for(int i=0;i<5;++i){
            tmp_bn1_var[i] = (double)pow(10,scaling_factor)/sqrt(tmp_bn1_var[i]);
            // printf("tmp_bn1_var[%d]=%f\n", i, tmp_bn1_var[i]);
            bn1_var[i] = (long long int)(tmp_bn1_var[i]);
        }

        // encrypt bn1_mean
        for(int i=0;i<5;++i){
            ciphertext_bn1_mean[i] = paillier_encryption(bn1_mean[i]);
            varbn[i] = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
            scalebn[i] = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
            mpz_init_set_si(varbn[i]->m, bn1_var[i]);
            mpz_init_set_si(scalebn[i]->m, bn1_scale[i]);
        }
    }

    void ConvParaInit(Config* config){
        int scaling_factor = config->getint("scaling_factor", 0);
        if(scaling_factor == 0){
            printf("No scaling_factor!\n");
        }
        FILE* conv_para_fp = NULL;
        char* conv_filter_file = config->getstring("conv_filter_file", NULL);
        conv_para_fp = fopen(conv_filter_file, "r");
        if(conv_para_fp == NULL){
            printf("can't open conv para file!\n");
        }
        double NumberFromFile = 0.0;
        int index = 0;
        while(fscanf(conv_para_fp, "%lf", &NumberFromFile) != EOF){
            tmp_conv_parameter_1[index] = NumberFromFile;
            index ++;
            if(index==25*5){
                break;
            }
        }
        fclose(conv_para_fp);
        conv_para_fp = NULL;

        // convert double to int: *scaling_factor
        for(int i=0;i<25*5;++i){
            tmp_conv_parameter_1[i] = tmp_conv_parameter_1[i]*pow(10,scaling_factor);
            convert_conv_parameter_1[i] = (int)(tmp_conv_parameter_1[i]);
            pt[i] = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
            mpz_init_set_si(pt[i]->m, convert_conv_parameter_1[i]);
        }

        /*
        // put conv para into 5 arrays
        for(int i=0;i<5;++i){
            for(int j=0;j<25;++j){
                conv_para_array_1[i][j] = convert_conv_parameter_1[i*25+j];
                // printf("%d ", conv_para_array_1[i][j]);
            }
            // printf("\n");
        }
        */
    }

    void init_conv_instructor(){
        for(int i=0;i<25;++i){
            for(int j=0;j<169;++j){
                conv_instructor[i][j] = 0;
            }
        }
        // printf("------------------------------------------\n");
        for(int i=0;i<5;++i){
            for(int j=0;j<5;++j){
                for(int k=0;k<13;++k){
                    for(int h=0;h<13;++h){
                        conv_instructor[i*5+j][k*13+h] = (i+2*k)*30 + (j+2*h);
                    }
                }
            }
        }
        nc::NdArray<int> tmp_assist_assay = nc::NdArray<int>(28,28);
        auto itt = tmp_assist_assay.begin();
        int index = 0;
        for(auto it=tmp_assist_assay.begin();it<tmp_assist_assay.end();++it){
            *itt = index;
            itt ++;
            index ++;
        }
        // initial_img_array.print();
        auto after_pad_array = nc::NdArray<int>(30, 30);
        after_pad_array = nc::pad(tmp_assist_assay, 1, -1);
        int padded_array[30*30];
        index = 0;
        for(auto it=after_pad_array.begin();it<after_pad_array.end();++it){
            padded_array[index] = *it;
            index ++;
        }
        for(int i=0;i<25;++i){
            for(int j=0;j<169;++j){
                conv_instructor[i][j] = padded_array[conv_instructor[i][j]];
                // printf("%d ", conv_instructor[i][j]);
            }
            // printf("\n-------------------------------\n");
        }
        
        /*
        for(int i=0;i<25;++i){
            for(int j=0;j<169;++j){
                if(conv_instructor[i][j]%30==0){
                    conv_instructor[i][j] = -1;
                }
                else if(conv_instructor[i][j]>0 && conv_instructor[i][j]<30){
                    conv_instructor[i][j] = -1;
                }
                else{
                    conv_instructor[i][j] = conv_instructor[i][j] - 30 - conv_instructor[i][j]/30;
                }
            }
            
        }
        */
        /*
        for(int i=0;i<25;++i){
            for(int j=0;j<169;++j){
                printf("%d ", conv_instructor[i][j]);
            }
            printf("\n");
        }
        */
    }

    void ComputeThreadInit(){
        /* init pubkey */
        sp_paillier_import_pubkey();
        collector_paillier_import_keys();

        Config* config = Config::getInstance();
        // load fc para
        ConvParaInit(config);

        // load bn para
        BNParaInit(config);

        
        // init cipher context
        res_to_merge = (paillier_cipher_array*)malloc(sizeof(paillier_cipher_array));
        init_paillier_cipher_array(res_to_merge);

        // init image structure
        init_cipher_struct();
        for(int i=0;i<28*28;++i){
            ciphertext_image[i] = (paillier_ciphertext_t*)malloc(sizeof(paillier_ciphertext_t));
            init_paillier_ciphertext(ciphertext_image[i]);
        }

        init_conv_instructor();

        // for decryption test
        value = 0;

        // for syn
        image_for_process_index = 0;

        // for fc1+bn1 func
        // pt = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
        paillier_ciphertext_res = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        mpz_init(paillier_ciphertext_res->c);
        // varbn = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
        // scalebn = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
        
        // for time parameter
        time_index = 0;
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

    void compute_conv(int compute_index, int filter_index, paillier_cipher_array* encryption_result){
        // init para
        paillier_ciphertext_t* ciphertext_conv_output;
        paillier_ciphertext_t* ciphertext_bn1_output;
        ciphertext_conv_output = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        ciphertext_bn1_output = (paillier_ciphertext_t *)malloc(sizeof(paillier_ciphertext_t));
        ciphertext_conv_output = paillier_encryption(0);
        ciphertext_bn1_output = paillier_encryption(0);
        // compute conv
        for(int j=0;j<25;++j){
            // mpz_init_set_si(pt->m, conv_para_array_1[filter_index][j]);
            if(conv_instructor[j][compute_index]!=-1){
                paillier_mul(re_paillier_pubkey, paillier_ciphertext_res, ciphertext_image[conv_instructor[j][compute_index]], pt[filter_index*25+j]);
                paillier_add(re_paillier_pubkey, ciphertext_conv_output, ciphertext_conv_output, paillier_ciphertext_res);
            }
        }
        // printf("index: %d, conv value: %lld\n", compute_index, pailliertext_decryption(ciphertext_conv_output));
        // compute bn1
        // mpz_init_set_si(varbn->m, bn1_var[filter_index]);
        // mpz_init_set_si(scalebn->m, bn1_scale[filter_index]);
        paillier_add(re_paillier_pubkey, ciphertext_bn1_output, ciphertext_conv_output, ciphertext_bn1_mean[filter_index]);
        paillier_mul(re_paillier_pubkey, ciphertext_bn1_output, ciphertext_bn1_output, varbn[filter_index]);
        paillier_mul(re_paillier_pubkey, ciphertext_bn1_output, ciphertext_bn1_output, scalebn[filter_index]);
        // decryption test
        // printf("index: %d, bn value: %lld\n", compute_index, pailliertext_decryption(ciphertext_bn1_output));
        char *enc_message;
        enc_message = paillier_ciphertext_to_str(ciphertext_bn1_output);
        encryption_result->c_length = ciphertext_bn1_output->c_length;
        for(int i=0;i<encryption_result->c_length;++i){
            encryption_result->array[i] = enc_message[i];
        }
        free(enc_message);
        enc_message = NULL;
        paillier_freeciphertext(ciphertext_conv_output);
        paillier_freeciphertext(ciphertext_bn1_output);
        ciphertext_conv_output = NULL;
        ciphertext_bn1_output = NULL;
    }

    void ComputeThreadFinish(){
        paillier_freepubkey(re_paillier_pubkey);
    }

    void ComputeThreadRecovery() {}

    void TerminateWindow1(char *ciphertext, int length, int i_index, char image_process_index) {
        VectorItem* cm_item = new VectorItem;
        // cm_item->AppendImageIndex(random_seed);
        cm_item->AppendCipher(ciphertext, length);
        cm_item->AppendCellIndex(i_index);
        cm_item->AppendImageIndex(image_process_index);
        EmitData(0, *cm_item);
        // just for test
        /*
        if(i_index<5){
            value = paillier_decryption(ciphertext, length);
            printf("value %d %lld\n", i_index, value);
        }
        */
        delete cm_item;
    }


    void ProcessData(uint32_t worker, uint32_t thread, uint64_t seq, afs::RawItem& tuple){
        char* line = tuple.raw_data;
        // gettimeofday(&starttime[time_index],NULL);
        if(strlen(line)>2){
            memcpy(&Image, line, sizeof(Image));
            for(int i=0;i<28*28;++i){
                formal_paillier_ciphertext_from_str(Image.paillier_cipher_image[i].array, Image.paillier_cipher_image[i].c_length, ciphertext_image[i]);
            }
            image_index = line[404544] - 1;
            // printf("%d %ld\n", image_index, pthread_self());
            randpermC(random_seed, 845, random_permutation_index);
            // generate in the upstream thread
            random_seed = line[404545];
            // printf("random_seed = %d\n", random_seed);
            int filter_index = image_index/5; // [0,4]
            int cipher_index = image_index%5; // [0,4]
            if(cipher_index==4){
                for(int j=0;j<33;++j){
                    compute_conv(136+j, filter_index, res_to_merge);
                    // ob
                    ob_index = random_permutation_index[filter_index*169+136+j];
                    TerminateWindow1(res_to_merge->array, res_to_merge->c_length, ob_index, image_for_process_index);
                    init_paillier_cipher_array(res_to_merge);
                }
            }
            else{
                for(int j=0;j<34;++j){
                    compute_conv(cipher_index*34+j, filter_index, res_to_merge);
                    // ob
                    ob_index = random_permutation_index[filter_index*169+cipher_index*34+j];
                    TerminateWindow1(res_to_merge->array, res_to_merge->c_length, ob_index, image_for_process_index);
                    init_paillier_cipher_array(res_to_merge);
                }
            }
        }
        image_for_process_index = (image_for_process_index+1);
        
    }

    void ProcessPunc() {}

};