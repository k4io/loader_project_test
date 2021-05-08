#pragma once

#define dll_name "dll_test.dll"
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "Memory.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "27015"

std::string encryptDecrypt(std::string toEncrypt) {
    char key[3] = { 'K', 'C', 'Q' };
    std::string output = toEncrypt;

    for (int i = 0; i < toEncrypt.size(); i++)
        output[i] = toEncrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];

    return output;
}