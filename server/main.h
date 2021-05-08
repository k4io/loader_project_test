#pragma once
#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "27015"

int i_connections = 0;

std::string encryptDecrypt(std::string toEncrypt);
std::ifstream::pos_type filesize(const char* filename);
void manageConnection(SOCKET s);