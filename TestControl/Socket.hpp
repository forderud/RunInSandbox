#pragma once
#include <Windows.h>
#include <Shlobj.h>

#pragma comment (lib, "Ws2_32.lib")


class SocketWrap {
public:
    SocketWrap() {
        WSADATA init_data = {};
        WSAStartup(MAKEWORD(2, 2), &init_data);

        m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(m_sock == INVALID_SOCKET) {
            //printf("Failed to create socket, error code: %d\n", WSAGetLastError());
            throw std::runtime_error("Failed to create socket");
        }
    }

    ~SocketWrap() {
        if (m_sock == INVALID_SOCKET)
            return;

        int res = closesocket(m_sock);
        if (res)
            std::terminate();
        m_sock = INVALID_SOCKET;

        res = WSACleanup();
        if (res == SOCKET_ERROR)
            std::terminate();
    }

    bool TryToConnect (const std::string& host, const uint16_t port) {
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host.c_str());
        addr.sin_port = htons(port);

        if(connect(m_sock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            if(WSAGetLastError() == WSAEACCES)
                ; // Connection blocked
            else
                ; // Connection unsuccessful but not blocked

            return false;
        }

        return true;
    }

private:
    SOCKET m_sock = INVALID_SOCKET;
};
