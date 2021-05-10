#pragma once
#undef UNICODE

#define WIN32_LEAN_AND_MEAN


#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <iomanip>
#include <string>
#include <array>
#include <string_view>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#ifdef OPENSSL_NO_HMAC
#error HMAC is disabled.
#endif


// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_PORT "27015"
const int BUFFERSIZE = 128;

int i_connections = 0;

std::string								encryptDecrypt		(std::string toEncrypt);
std::ifstream::pos_type					filesize			(const char* filename);
void									manageConnection	(SOCKET s, int clientnumber);
std::string								hmac256				(std::string data, std::string key);
static std::vector<unsigned char>		hmac_sha256			(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);