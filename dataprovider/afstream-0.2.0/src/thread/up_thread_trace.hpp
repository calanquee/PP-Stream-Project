#ifndef __AFS_INTHREAD_TRACE_HPP_INCLUDED__
#define __AFS_INTHREAD_TRACE_HPP_INCLUDED__

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

using namespace std;

namespace afs {

/**
 * Receive events outside the worker, executed by a single process
 * @tparam InT output class of dispatcher, used for input of compute_threads in the same worker
 */
template <class InT>
class UpThreadTrace : public UpThread<InT, NullClass> {

typedef WrapItem<InT> WInT;

public:
    UpThreadTrace(RouterBase* router);

    // derived from UpThread
    void AddOutQueue(ZeroRingBuffer<WInT>* q);

    void SetAdapter(AdapterBase* adapter);
    int index = 0;

protected:

    void Emit(void* data, uint32_t len) {
        int index = router_->GetDestination((InT*)data, sizeof(InT));
        WInT* slot = queues_[index]->GetSlot();
        slot->set_seq(event_);
        // LOG_MSG("Emit %lu\n", slot->get_seq());
        slot->set_type(ITEM_NORMAL);
        slot->data() = *(InT*)data;
        queues_[index]->CompleteWrite();
    }

private:
    AdapterBase* adapter_;
    //TraceParserBase<T>* parser_;
    RouterBase* router_;

    std::vector<ZeroRingBuffer<WInT>*> queues_;

    //  monitor number of process events
    uint64_t event_;
    uint64_t emit_succ_;
    uint64_t emit_fail_;
    double used_time_;

    // derived from ThreadBase
    void ThreadInitHandler();
    void ThreadFinishHandler();
    void ThreadMainHandler();
};

template<class InT>
UpThreadTrace<InT>::UpThreadTrace(
        RouterBase* router
        ) :
    UpThread<InT, NullClass>(),
    adapter_(NULL),
    router_(router),
    //parser_(parser),
    event_(0) {}

template<class T>
void UpThreadTrace<T>::AddOutQueue(ZeroRingBuffer<WInT>* q) {
    queues_.push_back(q);
}

template<class T>
void UpThreadTrace<T>::SetAdapter(AdapterBase* adapter) {
    adapter_ = adapter;
}

template<class T>
void UpThreadTrace<T>::ThreadInitHandler() {

    Config* config = Config::getInstance();

    /// set up adater
    char* adapter_type_str = config->getstring("adapter_type", NULL);
    afs_assert(adapter_type_str, "Adapter type is not specified\n");

    if (adapter_ == NULL) {
        PrintUseBuiltinAdapter();
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
            LOG_MSG("Network adapter is used!\n");
            adapter_ = new AdapterNetwork();
        }
        //else if (adapter_type == "dummy") {
        //    LOG_MSG("Dummy adapter is used\n");
        //    adapter_ = new AdapterDummy();
        //}
        else {
            PrintAdapterNotFound(adapter_type.c_str());
        }
    }

    adapter_->Init();
    // parser_->Init();
}

template<class T>
void UpThreadTrace<T>::ThreadMainHandler() {
    LOG_MSG("UpThreadTrace (%d) start to run\n", getpid());
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    //T* data;
    void* data;
    uint32_t len;
    while (1) {
        adapter_->ReadRecord(&data, &len);
        if (len == 1) {
            break;
        }
        if (len > 2){
            event_++;
            // printf("len = %d\n", len);
            Emit(data, len);
            index ++;
        }
    // parser_->ParseRecord(data, len);
    // ParseRecord(data, len);
    }
    // item finish
    /*
    WInT wrap_item;
    wrap_item.set_type(ITEM_FINISH);
    gettimeofday(&end_time, NULL);
    used_time_ = ((end_time.tv_sec + end_time.tv_usec / 1000000.0) -
                (start_time.tv_sec + start_time.tv_usec / 1000000.0));
    LOG_MSG("Finish seq %lu\n", wrap_item.get_seq());
    for (auto x : queues_ ) {
        x->Insert(&wrap_item);
    }
    for (auto x : queues_ ) {
        x->Flush();
    }
    printf("ITEM FINISH\n");
    */
}

template<class T>
void UpThreadTrace<T>::ThreadFinishHandler() {
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
