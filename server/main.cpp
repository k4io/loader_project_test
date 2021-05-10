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
    char recvbuf[BUFFERSIZE];
    int recvbuflen = BUFFERSIZE;

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
        std::thread connection(manageConnection, ClientSocket, i_connections);
        connection.detach();
        ClientSocket = 0;
    }
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}

void manageConnection(SOCKET s, const int clientnumber)
{
    int* authkey = nullptr;
    char recvbuf[BUFFERSIZE];
    int ClientSocket = s, recievedpackets = 0, iResult, iSendResult, cnum = clientnumber;
    i_connections += 1;
    std::cout << "[" << i_connections << "]" << " Client connected... { " << cnum << " }\n";
    std::ifstream filein("C:\\dll_test.dll", std::ios::binary);
    //std::ifstream filein("C:\\img.jpeg", std::ios::binary);

    // Receive until the peer shuts down the connection
    do {
        iResult = recv(ClientSocket, recvbuf, BUFFERSIZE, 0);
        if (iResult == -1)
        {
            printf("[%o] Client {{%o}} disconnected ", i_connections, cnum);
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
            printf("[%o] Client {{%o}} disconnected: recieved %s\n", i_connections, cnum, std::string(out).c_str());
            closesocket(ClientSocket);
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
            printf("[%o] { %o } Bytes sent: %ib *   ", i_connections, cnum, BUFFERSIZE);
            for (size_t i = 0; i < (buffer.size() / BUFFERSIZE) + 1; i++)
            {
                try {
                    //collect BUFFERSIZE bytes from vector
                    std::vector<char> localbuffer;
                    std::string sendbuffer{};
                    for (size_t j = (i * BUFFERSIZE); j < (i * BUFFERSIZE) + BUFFERSIZE; j++)
                        if (j < buffer.size())
                            sendbuffer += buffer[j] ^ *authkey;

                    iSendResult = send(ClientSocket, sendbuffer.c_str(), BUFFERSIZE, 0);
                    if (iSendResult == -1) {
                        printf("[%o] Client { %o } disconnected\n", i_connections, cnum);
                        i_connections -= 1; 
                        //WSACleanup();
                        return;
                    }

                    for (size_t j = 0; j < std::to_string(i).size(); j++)
                        printf("\b");
                    //if (std::to_string(i).size() > 1)
                    //    printf(" ");
                    printf("%i", i);

                    iResult = recv(ClientSocket, recvbuf, BUFFERSIZE, 0);
                    if (iResult == -1) {
                        printf("[%o] Client { %o } disconnected\n", i_connections, cnum);
                        i_connections -= 1;
                        //WSACleanup();
                        return;
                    }
                    std::string retstr = encryptDecrypt(recvbuf);
                    //printf("\n%s", retstr);
                    if (retstr.find("dOK") == std::string::npos)
                        break;
                    //SleepEx(250, false);
                }
                catch (...) 
                {
                    printf("[%o] { %o } An error occured when sending.", i_connections, cnum); 
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
        
        if (recievedpackets == 1)
        {
            char buffer[BUFFERSIZE]; //buffer for msg

            int unum = rand() % 4200000 + 133333337;
            std::string pwdhash = hmac256("kai123", "kai"); //encrypt pwdhash with key 'kai', pwd for now is static at 'kai123'
            std::string uniquehash = hmac256(std::to_string(unum), pwdhash); //encrypt unique number and key = hash of pwd

            std::string sendstr = encryptDecrypt("c." + std::to_string(unum));

            //send unique number as challenge
            iSendResult = send(ClientSocket, sendstr.c_str(), BUFFERSIZE, 0);

            memset(buffer, '\x00', BUFFERSIZE);

            //recieve answer
            iResult = recv(ClientSocket, buffer, BUFFERSIZE, 0);
            out = encryptDecrypt(std::string(buffer));
            std::string challenge_reply{};

            //is it an answer to the challenge?
            if (out[0] == 'r')
                challenge_reply = out.substr(2, out.size());
            else
            { //if not kill connection
                i_connections -= 1;
                printf("[%o] Client { %o } disconnected: recieved %s\n", i_connections, cnum, std::string(out).c_str());
                closesocket(ClientSocket);
                //WSACleanup();
                return;
            }

            if (challenge_reply == uniquehash)
            {
                iSendResult = send(ClientSocket, encryptDecrypt(std::string("OK").c_str()).c_str(), BUFFERSIZE, 0);

                std::string sendbuffer = "OK." + std::to_string(length);
                sendbuffer = encryptDecrypt(sendbuffer);
                iSendResult = send(ClientSocket, sendbuffer.c_str(), BUFFERSIZE, 0);
                authkey = &unum;
                continue;
            }
            i_connections -= 1;
            printf("[%o] Client { %o } disconnected: recieved %s\n", i_connections, cnum, std::string(out).c_str());
            closesocket(ClientSocket);
            return; //hash was not the same
        }

        if (iSendResult == -1) {
            i_connections -= 1;
            printf("[%o] Client { %o } disconnected: recieved %s\n", i_connections, cnum, std::string(out).c_str());
            closesocket(ClientSocket);
            //WSACleanup();
            return;
        }
        printf("[%o] { %o } Bytes sent: %d\n", i_connections, cnum, iSendResult);
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