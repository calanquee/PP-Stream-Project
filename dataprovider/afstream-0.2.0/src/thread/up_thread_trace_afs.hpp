#ifndef __AFS_INTHREAD_TRACE_AFS_HPP_INCLUDED__
#define __AFS_INTHREAD_TRACE_AFS_HPP_INCLUDED__

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/shm.h>

#include <string>

#include "../util.hpp"
#include "up_thread.hpp"

#include "adapter_base.hpp"
#include "adapter_disk.hpp"
#include "adapter_ram.hpp"
#include "adapter_network.hpp"
//#include "adapter_dummy.hpp"

#include "router_base.hpp"

#include "../fault_tolerance/adapter_recovery.hpp"
#include "../fault_tolerance/backup_item.hpp"
//#include "fault_tolerance/data_manager.hpp"

namespace afs {

/**
 * Receive events outside the worker, executed by a single process
 * @tparam InT output class of dispatcher, used for input of compute_threads in the same worker
 */
template <class InT>
class UpThreadTraceAFS : public UpThread<InT, NullClass> {

typedef WrapItem<InT> WInT;

private:

    void Backups(void* data, int len) {
        afs_zmq::command_t cmd;
        BackupItem& backup_item = cmd.args.backup_item;
        backup_item.data.meta.len = len;
        backup_item.data.meta.key = (event_) % 2000;
        if (len > MAX_BACKUP_ITEM_DATA_LEN) {
            LOG_ERR("Data too long to backup: data len %d, max backup %d\n", len, MAX_BACKUP_ITEM_DATA_LEN);
        }
        else {
            memcpy(backup_item.data.data, data, len);
        }
        if (backup_item.data.meta.len) {
            cmd.type = afs_zmq::command_t::backup;
            backup_item.info.backup_op = 0;
            backup_item.info.worker_id = ThreadBase::get_wid();
            backup_item.info.thread_id = thr_id();
            backup_item.info.op_index = 65535;
            backup_item.info.seq = event_;
            // LOG_MSG("len %d meta len %d seq %lu\n", len, backup_item.data.meta.len, backup_item.info.seq);
            ThreadBase::NotifyWorker(cmd);
            ThreadBase::WaitWorker(afs_zmq::command_t::backup, true);
            backup_item.data.meta.len = 0;
        }
    }

public:
    UpThreadTraceAFS(RouterBase* router);

    // derived from UpThread
    void AddOutQueue(ZeroRingBuffer<WInT>* q);

protected:

    void Emit(void* data, uint32_t len) {
        int index = router_->GetDestination((InT*)data, sizeof(InT));
        int s = queues_[index]->Size();
        if (max_data_lost_>=0 && s>max_data_lost_) {
            Backups(data, len);
        }
        WInT* slot = queues_[index]->GetSlot();
        slot->set_seq(event_);
        slot->set_type(ITEM_NORMAL);
        slot->data() = *(InT*)data;
        queues_[index]->CompleteWrite();
    }

private:
    AdapterBase* adapter_;
    //TraceParserBase<T>* parser_;
    RouterBase* router_;

    std::vector<ZeroRingBuffer<WInT>*> queues_;

    //DataManager* data_manager_;
    int max_data_lost_;

    //  monitor number of process events
    uint64_t event_;
    uint64_t emit_succ_;
    uint64_t emit_fail_;
    double used_time_;

    // derived from ThreadBase
    void ThreadInitHandler();
    void ThreadFinishHandler();
    void ThreadMainHandler();

    void DoRecovery() {
        // uint64_t start_ts = now_us();
        // AdapterRecovery* adapter_recovery = NULL;
        //     //data_manager_->RequestRecoveryData();
        // uint64_t end_ts = now_us();
        UpThread<InT, NullClass>::adapter_recovery_->Sort();

        uint64_t max_seq = UpThread<InT, NullClass>::adapter_recovery_->GetMaxSeq();
        LOG_MSG("Get max seq %lu\n", max_seq);

        BackupItem* bak_data;
        uint32_t len;
        while (1) {
            UpThread<InT, NullClass>::adapter_recovery_->ReadRecord((void**)&bak_data, &len);
            if (bak_data == NULL) {
                break;
            }

            printf("Recovery seq %lu data %d\n", bak_data->info.seq, len);

            event_ = bak_data->info.seq;
            Emit(&(bak_data->data.data), len);
        }

        event_ = 0;
        void* data;
        while (1) {
            adapter_->ReadRecord(&data, &len);
            if (data == NULL) {
                break;
            }

            event_++;
            if (event_ >= max_seq) {
                break;
            }
        }
        // LOG_MSG("Recovery time %lf\n", (end_ts-start_ts)/1000000.0);
        // printf("Recovery time %lf\n", (end_ts-start_ts)/1000000.0);
    }
};

template<class InT>
UpThreadTraceAFS<InT>::UpThreadTraceAFS(
        RouterBase* router
        ) :
    UpThread<InT, NullClass>(),
    router_(router),
    //parser_(parser),
    event_(0) {}

template<class T>
void UpThreadTraceAFS<T>::AddOutQueue(ZeroRingBuffer<WInT>* q) {
    queues_.push_back(q);
}

template<class T>
void UpThreadTraceAFS<T>::ThreadInitHandler() {

    Config* config = Config::getInstance();

    /// set up adater
    char* adapter_type_str = config->getstring("adapter_type", NULL);
    afs_assert(adapter_type_str, "Adapter type is not specified\n");

    std::string adapter_type(adapter_type_str);
    if (adapter_type == "ram") {
        LOG_MSG("RAM adapter is used\n");
        adapter_ = new AdapterRAM();
    }
    else if (adapter_type == "disk") {
        LOG_MSG("Disk adapter is used\n");
        adapter_ = new AdapterDisk();
    }
    else if (adapter_type == "network"){
        LOG_MSG("Network adapter is used\n");
        adapter_ = new AdapterNetwork();
    }
    //else if (adapter_type == "dummy") {
    //    LOG_MSG("Dummy adapter is used\n");
    //    adapter_ = new AdapterDummy();
    //}
    else {
        PrintAdapterNotFound(adapter_type.c_str());
    }

    adapter_->Init();

    // fault tolerance
    //data_manager_ = DataManager::GetInstance();
    max_data_lost_ = config->getint("sys.fault_tolerance.max_data_lost", -1);
    LOG_MSG("Max data lost %d\n", max_data_lost_);
}

template<class T>
void UpThreadTraceAFS<T>::ThreadMainHandler() {
    LOG_MSG("UpThreadTraceAFS (%d) start to run\n", getpid());

    if (UpThread<T, NullClass>::is_recovery && UpThread<T, NullClass>::adapter_recovery_) {
        DoRecovery();
    }

    // if (UpThread<T, NullClass>::is_recovery) {
    //     DoRecovery();
    // }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    //T* data;
    void* data;
    uint32_t len;
    while (1) {
        adapter_->ReadRecord(&data, &len);
        if (len == 0) {
            printf("BREAK\n");
            break;
        }

        event_++;

        Emit(data, len);
        //parser_->ParseRecord(data, len);
        //ParseRecord(data, len);
    }

    gettimeofday(&end_time, NULL);
    used_time_ = ((end_time.tv_sec + end_time.tv_usec / 1000000.0) -
                (start_time.tv_sec + start_time.tv_usec / 1000000.0));

    // LOG_MSG("To emit finish\n");
    for (auto x : queues_) {
        WInT* slot = x->GetSlot();
        slot->set_seq(event_);
        slot->set_type(ITEM_FINISH);
        x->CompleteWrite();
        x->Flush();
    }
    // WInT wrap_item;
    // wrap_item.set_type(ITEM_FINISH);
    // for (auto x : queues_) {
    //     x->Insert(&wrap_item);
    // }
    // for (auto x : queues_) {
    //     x->Flush();
    // }
    // LOG_MSG("After emit finish\n");
}

template<class T>
void UpThreadTraceAFS<T>::ThreadFinishHandler() {
    LOG_MSG(INDENT_HLINE INDENT
            "Total msgs %" PRIu64 ", "
            "Time %lf (s), "
            "Througput: %lf (msg/s)\n"
            INDENT_HLINE,
            event_,
            used_time_,
            event_ / used_time_);

    Config* config = Config::getInstance();
    char* throughput_file = config->getstring("throughput_benchmark", NULL);
    if (throughput_file) {
        FILE* tf = fopen(throughput_file, "a");
        fprintf(tf,
            "Total msgs %" PRIu64 ", "
            "Time %lf (s), "
            "Througput: %lf (msg/s)\n",
            event_,
            used_time_,
            event_ / used_time_);
        fclose(tf);
    }

    adapter_->Clean();
}

} // namespace

#endif // INCLUDE
