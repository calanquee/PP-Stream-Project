#ifndef __AFS_I_ADAPTER_HPP_INCLUDED__
#define __AFS_I_ADAPTER_HPP_INCLUDED__

#include "../util.hpp"

namespace afs {

void PrintUseBuiltinAdapter();
void PrintAdapterNotFound(const char* adapter_type);

class AdapterBase {

public:
    //virtual void AddSource(const char* source) = 0;

    virtual void ReadRecord(void** data, uint32_t *data_len) = 0;

    virtual void Init() = 0;
    virtual void Clean() = 0;

    virtual ~AdapterBase() {}

    /*
    virtual uint64_t CountMsg() = 0;
    virtual uint64_t CountByte() = 0;
    */
};

}

#endif
