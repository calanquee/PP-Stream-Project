#ifndef __AFS_RAW_ITEM_HPP_INCLUDED__
#define __AFS_RAW_ITEM_HPP_INCLUDED__

/// Original data from traces or external sources

#include <string.h>
#include "wrap_item.hpp"

namespace afs {

class RawItem {
public:
    char raw_data[MAX_RECORD_LENGTH];

    RawItem& operator= (RawItem& i) {
        //fprintf(stderr, "size %lu\n", strlen(i.raw_data));
        // memcpy(this->raw_data, i.raw_data, strlen(i.raw_data));
        // printf("111\n");
        memcpy(this->raw_data, i.raw_data, 405000);
        // printf("222\n");
        return *this;
    }
};

typedef WrapItem<RawItem> WRawItem;

}

#endif
