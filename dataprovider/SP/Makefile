service_provider1 : server.o paillier.o openssl_utils.o
	g++ -o service_provider1 server.o paillier.o openssl_utils.o -lcrypto -lssl -lgmp  -lpthread -L./home/liuqingxiu/demo7.0/afstream/bin -lzmq
paillier.o : paillier.cpp paillier.h
	g++ -c paillier.cpp
server.o : server.cpp paillier.h openssl_utils.h
	g++ -c server.cpp -std=c++17
openssl_utils.o : openssl_utils.cpp openssl_utils.h
	g++ -c openssl_utils.cpp -std=c++17
clean :
	rm service_provider1 server.o paillier.o openssl_utils.o

