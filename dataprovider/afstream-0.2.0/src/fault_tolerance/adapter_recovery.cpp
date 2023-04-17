#include "adapter_recovery.hpp"

namespace afs {

int cmp_backup (const void * a, const void * b) {
    BackupItem* t1 = (BackupItem*)a;
    BackupItem* t2 = (BackupItem*)b;
    
    return t1->info.seq > t2->info.seq;
}

AdapterRecovery::AdapterRecovery() :
    data_buf_(NULL) {
        data_buf_ = (BackupItem*)calloc(2000, sizeof(BackupItem));
        afs_assert(data_buf_, "Data buffer allocate failure\n");

        cnt = 0;
        cur = 0;
    }

void AdapterRecovery::AppendBackupItem(BackupItem* bak_item) {
    data_buf_[cnt] = *bak_item;
    if (data_buf_[cnt].info.seq > max_seq) {
        max_seq = data_buf_[cnt].info.seq;
    }
    cnt++;
}

uint64_t AdapterRecovery::GetMaxSeq() {
    return max_seq;
}

void AdapterRecovery::SetMaxSeq(uint64_t s) {
    max_seq = s;
}

void AdapterRecovery::Init() {
}

void AdapterRecovery::Sort() {
    qsort(data_buf_, cnt, sizeof(BackupItem), cmp_backup);
}

void AdapterRecovery::Clean() {
    free(data_buf_);
}

/*
void AdapterRecovery::AddSource(const char* source) {
    LOG_ERR("We only consider single file for adapter_disk\n");
}
*/

// assume each record is a one-line, readable string
void AdapterRecovery::ReadRecord(void** data, uint32_t *data_len) {
    if (cur == cnt) {
        *data = NULL;
        return;
    }
    *data = data_buf_+cur;
    *data_len = data_buf_[cur].data.meta.len;
    cur++;
}
}
