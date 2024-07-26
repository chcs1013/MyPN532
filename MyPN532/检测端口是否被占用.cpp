#include <iostream>  
#include <winsock2.h>  
#include <ws2tcpip.h>  
#pragma comment(lib, "ws2_32.lib") // ���ӵ�WS2_32.lib  

bool ���˿��Ƿ�ռ��(unsigned short Ҫ���Ķ˿ں�) {
    // ��ʼ��Winsock  
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return true;
    }

    // ����socket  
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return true;
    }

    // ��socket�����ص�ַ�Ͷ˿�  
    sockaddr_in service{};
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY; // �������б��ص�ַ  
    service.sin_port = htons(Ҫ���Ķ˿ں�);

    if (bind(sock, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error == WSAEADDRINUSE) {
            // �˿��ѱ�ռ��  
            closesocket(sock);
            WSACleanup();
            return true;
        }
        else {
            closesocket(sock);
            WSACleanup();
            return true;
        }
    }

    // ����󶨳ɹ���˵���˿�δ��ռ�ã�������ʵ���ϲ���Ҫ���socket  
    closesocket(sock);
    WSACleanup();
    return false;
}
