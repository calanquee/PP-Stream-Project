#include <stdlib.h>
#include <string>

#include "relu_merge_thread.hpp"
#include "paillier.h"
// #include "paillier_structure.h"


int main(int argc, char* argv[]) {
    // worker name is used to find out the corresponding config section in the config file
    if (argc != 4) {
        LOG_MSG("Requires: Command [Config file] [Worker Name] [Is Recovery]\n");
        return -1;
    }

    char* config_name = argv[1];
    char* worker_name = argv[2];
    int recovery = atoi(argv[3]);

    Config *config = Config::getInstance(config_name, worker_name);

    int num_compute_thread = config->getint("num_compute_threads", 0);
    if (num_compute_thread == 0) {
        LOG_MSG("[num_compute_threads] must be specified in the config file: at least 1\n");
        return -1;
    }

    // create worker
    int worker_id = config->getint("worker_id", -1);
    afs_assert(worker_id>=0, "worker id is not specified in config file\n");
    afs::Worker<struct VectorItem, struct ReLUItem, afs::NullClass, afs::NullClass>* worker =
        new afs::Worker<struct VectorItem, struct ReLUItem, afs::NullClass, afs::NullClass>(std::string(worker_name), worker_id, std::string(""), num_compute_thread);

    /*
    char* addr = config->getstring("listen_addr", NULL);
    if (addr == NULL) {
        LOG_MSG("[listen addr] must be specified in the config file\n");
        return -1;
    }
    */

    int num_in = config->getint("num_upstreams", 0);
    if(num_in){
        afs::UpThreadNet<struct VectorItem, afs::NullClass>* i_thread =
        new afs::UpThreadNet<struct VectorItem, afs::NullClass>(num_in, num_compute_thread,1);
        std::string prefix("listen_addr");
        for (int i=0; i<num_in; i++) {
            char tmp[10];
            sprintf(tmp, "%d", i);
            std::string key = prefix + tmp;
            char* addr = config->getstring(key.c_str(), NULL);
            // printf("listen_add: %s", addr);
            i_thread->AddSource(addr);
        }
        worker->AddUpThread(i_thread);
    }
    
    int num_downstream = config->getint("num_downstreams", 0);
    for (int i=0; i<num_compute_thread; i++) {
        MergeThread* compute_thread =
            new MergeThread(num_in, num_downstream);
        worker->AddComputeThread(compute_thread);
    }


    if (num_downstream) {
        afs::DownThreadNet<struct ReLUItem, afs::NullClass>* o_thread = new afs::DownThreadNet<struct ReLUItem, afs::NullClass>(num_compute_thread, num_downstream);
        std::string prefix("downstream_addr");
        for (int i=0; i<num_downstream; i++) {
            char tmp[10];
            sprintf(tmp, "%d", i);
            std::string key = prefix + tmp;
            char* addr = config->getstring(key.c_str(), NULL);
            // printf("downstream_addr: %s", addr);
            o_thread->AddDest(i, addr);
        }
        worker->AddDownThread(o_thread);
    }

    // Start
    worker->Start(recovery);

    return 0;
}