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
all: relu_cm_worker fc3_merge_worker relu_merge_worker
#fc3_cm_worker


relu_cm_worker: relu_cm_worker.cpp paillier.cpp
	$(CC) relu_cm_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o relu_cm_worker

relu_merge_worker: relu_merge_worker.cpp paillier.cpp
	$(CC) relu_merge_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o relu_merge_worker

fc3_merge_worker: fc3_merge_worker.cpp paillier.cpp
	$(CC) fc3_merge_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o fc3_merge_worker

#fc3_cm_worker: fc3_cm_worker.cpp paillier.cpp
#	$(CC) fc3_cm_worker.cpp paillier.cpp $(CFLAGS) $(HEADER) $(LIBB) -o fc3_cm_worker


clean:
	rm -rf relu_cm_worker fc3_merge_worker relu_merge_worker
#fc3_cm_worker

