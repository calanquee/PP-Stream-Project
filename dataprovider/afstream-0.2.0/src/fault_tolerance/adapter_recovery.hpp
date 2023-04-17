#ifndef __AFS_ADAPTER_RECOVERY_HPP_INCLUDED__
#define __AFS_ADAPTER_RECOVERY_HPP_INCLUDED__

#include "backup_item.hpp"
#include "../thread/adapter_base.hpp"

#include <stdio.h>
#include <string>

#include "../config.hpp" 
#include "../util.hpp"
#include "../params.hpp"

#define RECOVER_SIZE MAX_BACKUP_ITEM_DATA_LEN*1000

namespace afs {

class AdapterRecovery : public AdapterBase {

public:

    // derived from AdapterBase
    void Init();
    void Clean();
    //void AddSource(const char* source);

    AdapterRecovery();

    // derived from AdapterBase
    void ReadRecord(void** data, uint32_t *len);

    void AppendBackupItem(BackupItem* bak_item);

    uint64_t GetMaxSeq();
    void SetMaxSeq(uint64_t s);

    void Sort();

private:

    BackupItem* data_buf_;
    uint64_t cnt;
    uint64_t cur;
    uint64_t max_seq;
};

}
#endif

