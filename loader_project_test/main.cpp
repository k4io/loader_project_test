#include "main.h"

int __cdecl main(int argc, char** argv)
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    const char* sendbuf = "loginfatcock";
    std::string out = encryptDecrypt(sendbuf);
    char recvbuf[2048];
    int iResult;
    int recvbuflen = 2048;


    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    iResult = send(ConnectSocket, out.c_str(), (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes Sent: %ld\n", iResult);

    // Receive until the peer closes the connection
    do {
        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);

        send(ConnectSocket, std::string(encryptDecrypt("clone")).c_str(), 2048, 0);

        std::string recievedStr(encryptDecrypt(recvbuf));
        if (recievedStr.find("OK") != std::string::npos)
        {
            int size = stoi(
                recievedStr.substr(
                    recievedStr.find(".") + 1
                    , recievedStr.size()
                )
            );
            printf("Filesize: %o\n", size);
            std::vector<char> filearray{};
            for (size_t i = 0; i < (size / 2048) + 1; i++)
            {
                for (size_t j = 0; j < 2048; j++)  
                    recvbuf[j] = 0;

                iResult = recv(ConnectSocket, recvbuf, 2048, 0);

                //recvbuf = encryptDecrypt(recvbuf).c_str();

                for (size_t j = 0; j < 2048; j++)
                    filearray.push_back(recvbuf[j] ^ '\x29');

                char sendarr[2048];
                sendarr[0] = 'd';
                sendarr[1] = 'O';
                sendarr[2] = 'K';

                send(ConnectSocket, encryptDecrypt("dOK").c_str(), 2048, 0);
            }
            send(ConnectSocket, encryptDecrypt("goodbye").c_str(), 2048, 0);
            closesocket(ConnectSocket);
            WSACleanup();
            printf("Filearray: %o\n", filearray.size());

            //std::ofstream fileout("dll_test_out123.dll", std::ios::out | std::ios::binary);
            //fileout.write(&filearray[0], filearray.size());

           // memory _mem{};
            DWORD _pid = getProcess("cockshortcuts.exe");

            HANDLE _hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _pid);

            if (!_hProc)
            {
                printf("OpenProcess failed with code: 0x%X\n", std::to_string(GetLastError()));
                system("pause");
                return 0;
            }

            if (!_map(_hProc, &filearray))
            {
                CloseHandle(_hProc);
                printf("_map failed with code: 0x%X\n", std::to_string(GetLastError()));
                system("pause");
                return 0;
            }
            printf("Manual mapping was successful.");
            CloseHandle(_hProc);
            return 0;
        }

        if (iResult > 0)
            printf("Bytes received: %d\n", iResult);
        else if (iResult == 0)
            printf("Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

    } while (iResult > 0);

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}