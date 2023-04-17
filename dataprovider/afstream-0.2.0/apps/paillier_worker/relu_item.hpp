#include <stdint.h>
#include <utility>
#include "paillier.h"
//#include "util.hpp"

struct __attribute__ ((__packed__)) ReLUItem {
    char image_index;
    int cell_index;
    char relu_result_buf[845*516];

    ReLUItem() : cell_index(0) {}

    void AppendCellIndex(int value){
        cell_index = value;
    }

    void AppendReLUResult(char *result){
        memcpy(relu_result_buf, result, 845*516);
    }

    void AppendImageIndex(char value){
        image_index = value;
    }

};
