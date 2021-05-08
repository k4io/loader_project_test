#include "main.h"

int __cdecl main(void)
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    
    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    // Accept a client socket
    while (1) {
        //std::cout << "[" << i_connections << "]" << " Waiting for client...\n";

        ClientSocket = accept(ListenSocket, NULL, NULL);

        if (ClientSocket == INVALID_SOCKET) {
            printf("accept failed with error: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }
        std::thread connection(manageConnection, ClientSocket);
        connection.detach();
        ClientSocket = 0;
    }
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}

void manageConnection(SOCKET s)
{
    char recvbuf[2048];
    int ClientSocket = s, recievedpackets = 0, iResult, iSendResult;
    i_connections += 1;
    std::cout << "[" << i_connections << "]" << " Client connected...\n";
    std::ifstream filein("C:\\dll_test_new.dll", std::ios::binary);
    //std::ifstream filein("C:\\img.jpeg", std::ios::binary);

    // Receive until the peer shuts down the connection
    do {
        iResult = recv(ClientSocket, recvbuf, 2048, 0);
        if (iResult == -1)
        {
            printf("[%o] Client disconnected", i_connections);
            i_connections -= 1;
            //WSACleanup();
            return;
        }
        //std::string recvstr(encryptDecrypt(recvbuf));
        std::string out = encryptDecrypt(recvbuf);
        recievedpackets += 1;

        if (std::string(out).find("loginfatcock") == std::string::npos
            && recievedpackets == 1)
        {
            i_connections -= 1;
            printf("[%o] Client disconnected: recieved %s\n", i_connections, std::string(out).c_str());
            closesocket(ClientSocket);
            //WSACleanup();
            return;
        }
        if (std::string(out) == "clone"
            && recievedpackets == 2)
        {
            std::string byteString = "";
            //send file array
            std::vector<char> buffer;

            //get length of file
            filein.seekg(0, filein.end);
            size_t length = filein.tellg();
            filein.seekg(0, filein.beg);

            //read file
            if (length > 0) {
                buffer.resize(length);
                filein.read(&buffer[0], length);
            }

            //send dll as bytes
            printf("[%o] Bytes sent: 2048 *  ", i_connections);
            for (size_t i = 0; i < (buffer.size() / 2048) + 1; i++)
            {
                try {
                    //collect 2048 bytes from vector
                    std::vector<char> localbuffer;
                    std::string sendbuffer{};
                    for (size_t j = (i * 2048); j < (i * 2048) + 2048; j++)
                        if (j < buffer.size())
                            sendbuffer += buffer[j] ^ '\x29';

                    iSendResult = send(ClientSocket, sendbuffer.c_str(), 2048, 0);
                    if (iSendResult == -1) {
                        printf("[%o] Client disconnected", i_connections);
                        i_connections -= 1;
                        //WSACleanup();
                        return;
                    }
                    printf("\b%o", i);
                    iResult = recv(ClientSocket, recvbuf, 2048, 0);
                    if (iResult == -1) {
                        printf("[%o] Client disconnected", i_connections);
                        i_connections -= 1;
                        //WSACleanup();
                        return;
                    }
                    std::string retstr = encryptDecrypt(recvbuf);
                    //printf("\n%s", retstr);
                    if (retstr.find("dOK") == std::string::npos)
                        break;
                    SleepEx(250, false);
                }
                catch (...) 
                {
                    printf("[%o] An error occured when sending.", i_connections); 
                   // WSACleanup();
                    i_connections -= 1;
                    return;
                }
            }
            printf("\n");
        }
        else if(std::string(out).find("goodbye") != std::string::npos)
        {
            i_connections -= 1;
            printf("[%o] Client disconnected: recieved %s\n", i_connections, std::string(out).c_str());
            closesocket(ClientSocket);
            return;
            //WSACleanup();
        }
        if (recievedpackets != 1) continue;
        filein.seekg(0, filein.end);
        size_t length = filein.tellg();
        filein.seekg(0, filein.beg);
        // Echo the buffer back to the sender
        std::string sendbuffer = "OK." + std::to_string(length);
        sendbuffer = encryptDecrypt(sendbuffer);
        iSendResult = send(ClientSocket, sendbuffer.c_str(), 2048, 0);

        if (iSendResult == -1) {
            i_connections -= 1;
            printf("[%o] Client disconnected: recieved %s\n", i_connections, std::string(out).c_str());
            closesocket(ClientSocket);
            //WSACleanup();
            return;
        }
        printf("[%o] Bytes sent: %d\n", i_connections, iSendResult);
    } while (ClientSocket != -1);
}

std::string encryptDecrypt(std::string toEncrypt) {
    char key[3] = { 'K', 'C', 'Q' };
    std::string output = toEncrypt;

    for (int i = 0; i < toEncrypt.size(); i++)
        output[i] = toEncrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];

    return output;
}

std::ifstream::pos_type filesize(const char* filename)
{
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}