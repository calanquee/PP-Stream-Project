#pragma once

#include <cstdint>

#include <string>
#include <vector>

std::vector<char> GenerateRsaSignByFile(unsigned char * message, const std::string& pri_filename);

std::vector<char> GenerateRsaSignByString(unsigned char * message, const std::string& prikey);

bool VerifyRsaSignByFile(char* sign, uint32_t sign_len, const std::string& pub_filename, unsigned char * verify_str);

bool VerifyRsaSignByString(char* sign, uint32_t sign_len, const std::string& pubkey, unsigned char * verify_str);
