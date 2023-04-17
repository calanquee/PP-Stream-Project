# Compiler
CC = g++

# Compiling options
CFLAGS = -Wall -std=c++14

#ifeq ($(BUILD), debug)
# "Debug" build - no optimization, and debugging symbols
#CFLAGS += -O0 -g
#else
# "Release" build - optimization, and no debug symbols
CFLAGS += -O2 -g -s -DNDEBUG
#endif

# Compiling header and libs
HEADER = -I./../../include -I./../../third_party/zeromq/include
LIBB = -L./../../bin -lpthread -lafstream -lzmq -lcrypto -lssl -lgmp -lm
#LIBB = libafstream.a -L./../../build.tmp
#LIBRA = -lpthread -ldl -larmadillo

# Compiling rules 
all: conv_cm_worker fc2_cm_worker fc3_cm_worker
#fc_cm_worker 

conv_cm_worker: conv_cm_worker.cpp paillier.cpp
	$(CC) conv_cm_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o conv_cm_worker

#fc_cm_worker: fc_cm_worker.cpp paillier.cpp
#	$(CC) fc_cm_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o fc_cm_worker

fc2_cm_worker: fc2_cm_worker.cpp paillier.cpp
	$(CC) fc2_cm_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o fc2_cm_worker

fc3_cm_worker: fc3_cm_worker.cpp paillier.cpp
	$(CC) fc3_cm_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o fc3_cm_worker


clean:
	rm -rf conv_cm_worker fc2_cm_worker fc3_cm_worker
#fc_cm_worker  
