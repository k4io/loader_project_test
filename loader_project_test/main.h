#pragma once

#define dll_name "dll_test.dll"
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <array>
#include <string_view>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
//#include <stdio.h>

#include "Memory.h"

#include <openssl/err.h>
#include <openssl/ssl.h>    
#include <openssl/hmac.h>
#include <openssl/sha.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "urlmon.lib")

#define DEFAULT_PORT "27015"
const int BUFFERSIZE    = 512;
long* authkey{nullptr};

static std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);

std::string encryptDecrypt(std::string toEncrypt) {
    std::string key{};
    if (authkey == nullptr)
        key = "POU";
    else 
        key = std::to_string(*authkey);
    std::string output = toEncrypt;

    for (int i = 0; i < toEncrypt.size(); i++)
        output[i] = (toEncrypt[i] ^ key[i % key.size()]);

    return output;
}

std::string hmac256(std::string data, std::string key)
{
    std::vector<unsigned char> secret(data.begin(), data.end());
    std::vector<unsigned char> msg(key.begin(), key.end());

    std::vector<unsigned char> out = hmac_sha256(msg, secret);

    std::string strout{};

    for (size_t i = 0; i < out.size() - 1; i++)
        strout += out[i];

    return strout;
}

static std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key)
{
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<unsigned char> digest(len);


    HMAC_CTX* ctx = HMAC_CTX_new();
    //HMAC_Init_ex(h, key, keylen, EVP_sha256(), NULL);
    
    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), NULL);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, digest.data(), &len);

    //HMAC_CTX_cleanup(ctx);
    HMAC_CTX_free(ctx);

    return digest;
}