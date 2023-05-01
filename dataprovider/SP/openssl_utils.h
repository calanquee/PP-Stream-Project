#pragma once

#include <cstdint>

#include <string>
#include <vector>

// 生成签名通过私钥文件
std::vector<char> GenerateRsaSignByFile(unsigned char * message, const std::string& pri_filename);

// 生成签名通过私钥字符串
std::vector<char> GenerateRsaSignByString(unsigned char * message, const std::string& prikey);

// 验证签名通过公钥文件
bool VerifyRsaSignByFile(char* sign, uint32_t sign_len, const std::string& pub_filename, unsigned char * verify_str);

// 验证签名通过公钥字符串
bool VerifyRsaSignByString(char* sign, uint32_t sign_len, const std::string& pubkey, unsigned char * verify_str);
