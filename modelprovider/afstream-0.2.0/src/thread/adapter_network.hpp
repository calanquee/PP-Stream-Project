#ifndef __AFS_ADAPTER_NETWORK_HPP_INCLUDED__
#define __AFS_ADAPTER_NETWORK_HPP_INCLUDED__

#define MAX_NET_DATA 410000
#include "adapter_base.hpp"

#include <stdio.h>
#include <string>

#include "../config.hpp"
#include "../util.hpp"

#include "../net/epoll.hpp"
#include "../net/options.hpp"
#include "../net/address.hpp"
#include "../net/tcp_connecter.hpp"
#include <zmq.h>

namespace afs {

class AdapterNetwork : public AdapterBase {

public:

    // derived from AdapterBase
    void Init();
    void Clean();
    // void AddSource(const char* source);

    AdapterNetwork();

private:
    void *context;
    void *responder;
    char buf[MAX_NET_DATA];
    int rc;
    int nbyte;

    // derived from AdapterBase
    void ReadRecord(void** data, uint32_t *data_len);
};

AdapterNetwork::AdapterNetwork() :
    context(NULL),
    responder(NULL),
    rc(0),
    nbyte(0) { }

void AdapterNetwork::Init() {
    Config* config = Config::getInstance();
    char* addr = config->getstring("sender_address", NULL);
    context = zmq_ctx_new();
    responder = zmq_socket(context, ZMQ_PULL);
    rc = zmq_bind(responder, addr);
    assert(rc == 0);
}

void AdapterNetwork::Clean() {
    zmq_close(responder);
    zmq_ctx_destroy(context);
}


// assume each record is a one-line, readable string
void AdapterNetwork::ReadRecord(void** data, uint32_t *data_len) {
    nbyte = zmq_recv(responder, buf, MAX_NET_DATA, ZMQ_DONTWAIT); //replace: ZMQ_DONTWAIT
    if(nbyte == 1){
        *data = NULL;
        *data_len = 1;
    }
    else if(nbyte == -1){
        *data = NULL;
        *data_len = 0;
    }
    else{
        buf[404545] = 1;
        *data = buf;
        *data_len = nbyte;
        *data_len += nbyte;
        /*
        if(nbyte>0){
            // printf("%d\n", (buf[101139]-1)*100 + (buf[101140]-1));
            printf("nbyte = %d\n", nbyte);
            printf("adapter length = %d\n", strlen(buf));
        }
        */
    }
}

}
#endif
