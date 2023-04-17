#include "adapter_base.hpp"

namespace afs {
char adapter_types[] = "\n    =============\n"
                        "    ram\n"
                        "    disk\n"
                        //"dummy\n"
                        "\n    =============\n";

void PrintUseBuiltinAdapter() {
    LOG_MSG("    No user-specified adapters, search configure file for a built-in adapter\n");
}

void PrintAdapterNotFound(const char* adapter_type) {
    LOG_ERR("Adapter type %s is not supported!\n"
            "Existing adaters include:%s",
            adapter_type, adapter_types);
}
}
