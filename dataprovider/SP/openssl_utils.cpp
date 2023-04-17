#include "openssl_utils.h"

#include <iostream>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// 私钥：PEM_read_bio_RSAPrivateKey
// 公钥：PEM_read_bio_RSA_PUBKEY

std::vector<char> GenerateRsaSignByFile(unsigned char *message, const std::string& pri_filename) {
    OpenSSL_add_all_algorithms();
    BIO* in = BIO_new(BIO_s_file());
    if (in == NULL) {
        std::cout << "BIO_new failed" << std::endl;
        return std::vector<char>();
    }
    BIO_read_filename(in, pri_filename.c_str());
    RSA* rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    if (rsa == NULL) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }
    unsigned int size = RSA_size(rsa);
    std::vector<char> sign;
    sign.resize(size);
    int ret = RSA_sign(NID_md5, (const unsigned char*)message, 64, (unsigned char*)sign.data(), &size, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_sign failed" << std::endl;
        return std::vector<char>();
    }
    return sign;
}

std::vector<char> GenerateRsaSignByString(unsigned char * message,const std::string& prikey) {
    OpenSSL_add_all_algorithms();
    BIO* in = BIO_new_mem_buf((void*)prikey.c_str(), -1);
    if (in == NULL) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return std::vector<char>();
    }
    RSA* rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    if (rsa == NULL) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }
    unsigned int size = RSA_size(rsa);
    std::vector<char> sign;
    sign.resize(size);
    int ret = RSA_sign(NID_md5, (const unsigned char*)message,64, (unsigned char*)sign.data(), &size, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_sign failed" << std::endl;
        return std::vector<char>();
    }
    return sign;
}

bool VerifyRsaSignByFile(char* sign, uint32_t sign_len, const std::string& pub_filename, unsigned char * verify_str) {
    OpenSSL_add_all_algorithms();
    BIO* in = BIO_new(BIO_s_file());
    if (in == NULL) {
        std::cout << "BIO_new failed" << std::endl;
        return false;
    }
    BIO_read_filename(in, pub_filename.c_str());
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
    if (rsa == NULL) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return false;
    }
    BIO_free(in);
    int ret = RSA_verify(NID_md5, (const unsigned char*)verify_str, 64, (unsigned char*)sign, sign_len, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_verify failed" << std::endl;
        return false;
    }
    return true;
}

bool VerifyRsaSignByString(char* sign, uint32_t sign_len, const std::string& pubkey, unsigned char * verify_str) {
    BIO* in = BIO_new_mem_buf((void*)pubkey.c_str(), -1);
    if (in == NULL) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return false;
    }
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
    BIO_free(in);
    if (rsa == NULL) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return false;
    }
    int ret = RSA_verify(NID_md5, (const unsigned char*)verify_str, 64, (unsigned char*)sign, sign_len, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_verify failed" << std::endl;
        return false;
    }
    return true;
}
