#include <stdint.h>
#include <utility>
#include "paillier.h"
//#include "util.hpp"

struct __attribute__ ((__packed__)) VectorItem {
    char image_index;
    char cipher_array[512];
    int cipher_length;
    int cell_index;
    
    VectorItem() : cipher_length(0) {}

    void AppendCipher(char *value, int length){
        for(int i=0;i<length;++i){
            cipher_array[i] = value[i];
        }
        cipher_length = length;
    }

    void AppendCellIndex(int value){
        cell_index = value;
    }

    void AppendImageIndex(char value){
        image_index = value;
    }

};


