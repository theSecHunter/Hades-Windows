/*
* 项目: github - KSOCKET-master
* 封装wsk接口
*   [wsk-msdn]: <https://docs.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-winsock-kernel>
    [wsk-http]: <https://github.com/reinhardvz/afdmjhk/blob/master/WSK/Samples/wsksample/wsksample.c>
    [wsk-echosrv]: <https://github.com/Microsoft/Windows-driver-samples/tree/master/network/wsk/echosrv>

Demo Use Entry:
  //
  // Initialize KSOCKET.
  //

  Status = KsInitialize();

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Client.
  // Perform HTTP request to http://httpbin.org/uuid
  //

  {
    int result;

    char send_buffer[] =
      "GET /uuid HTTP/1.1\r\n"
      "Host: httpbin.org\r\n"
      "Connection: close\r\n"
      "\r\n";

    char recv_buffer[1024] = { 0 };

    struct addrinfo hints = { 0 };
    hints.ai_flags |= AI_CANONNAME;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    result = getaddrinfo("httpbin.org", "80", &hints, &res);

    int sockfd;
    sockfd = socket_connection(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    result = connect(sockfd, res->ai_addr, (int)res->ai_addrlen);
    result = send(sockfd, send_buffer, sizeof(send_buffer), 0);
    result = recv(sockfd, recv_buffer, sizeof(recv_buffer), 0);
    recv_buffer[sizeof(recv_buffer) - 1] = '\0';

    DebuggerPrint("TCP client:\n%s\n", recv_buffer);

    closesocket(sockfd);
  }

  //
  // TCP server.
  // Listen on port 9095, wait for some message,
  // then send our buffer and close connection.
  //
  // Try:
  // > nc 127.0.0.1 9095 [enter]
  // > HELLO FROM USERMODE! [enter]
  // > Hello from WSK! [expected response]
  //

  {
    int result;

    char send_buffer[] = "Hello from WSK!";
    char recv_buffer[1024] = { 0 };

    int server_sockfd = socket_listen(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(9095);

    result = bind(server_sockfd, (struct sockaddr*)&addr, sizeof(addr));
    result = listen(server_sockfd, 1);

    socklen_t addrlen = sizeof(addr);
    int client_sockfd = accept(server_sockfd, (struct sockaddr*)&addr, &addrlen);

    result = recv(client_sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0);
    recv_buffer[sizeof(recv_buffer) - 1] = '\0';

    DebuggerPrint("TCP server:\n%s\n", recv_buffer);

    result = send(client_sockfd, send_buffer, sizeof(send_buffer), 0);

    closesocket(client_sockfd);
    closesocket(server_sockfd);
  }

  //
  // Destroy KSOCKET.
  //

  KsDestroy();

  //
  // Unload the driver immediately.
  //
*/

#include "public.h"
#include <wsk.h>
#include "kwsk.h"
#include "ksuse.h"

WSK_PROVIDER_NPI     WskProvider;
WSK_REGISTRATION     WskRegistration;
WSK_CLIENT_DISPATCH  WskDispatch1 = { MAKE_WSK_VERSION(1,0), 0, NULL };

#define MEMORY_TAG            ' bsK'
#define SOCKETFD_MAX          128
#define TO_SOCKETFD(index)    ((index % SOCKETFD_MAX)  + 1)
#define FROM_SOCKETFD(sockfd) ((sockfd)                - 1)

PKSOCKET KsArray[SOCKETFD_MAX] = { 0 };
ULONG    KsIndex = 0;

typedef struct _KSOCKET KSOCKET, * PKSOCKET;

int socket_connection(int domain, int type, int protocol)
{
    NTSTATUS Status;
    PKSOCKET Socket;

    Status = KsCreateConnectionSocket(
        &Socket,
        (ADDRESS_FAMILY)domain,
        (USHORT)type,
        (ULONG)protocol
    );

    if (NT_SUCCESS(Status))
    {
        int sockfd = TO_SOCKETFD(KsIndex++);

        KsArray[FROM_SOCKETFD(sockfd)] = Socket;

        return sockfd;
    }

    return -1;
}

int socket_listen(int domain, int type, int protocol)
{
    NTSTATUS Status;
    PKSOCKET Socket;

    //
    // WskSocket() returns STATUS_PROTOCOL_UNREACHABLE (0xC000023E)
    // when Protocol == 0, so coerce this value to IPPROTO_TCP here.
    //

    Status = KsCreateListenSocket(
        &Socket,
        (ADDRESS_FAMILY)domain,
        (USHORT)type,
        protocol ? (ULONG)protocol : IPPROTO_TCP
    );

    if (NT_SUCCESS(Status))
    {
        int sockfd = TO_SOCKETFD(KsIndex++);

        KsArray[FROM_SOCKETFD(sockfd)] = Socket;

        return sockfd;
    }

    return -1;
}

int socket_datagram(int domain, int type, int protocol)
{
    NTSTATUS Status;
    PKSOCKET Socket;

    Status = KsCreateDatagramSocket(
        &Socket,
        (ADDRESS_FAMILY)domain,
        (USHORT)type,
        (ULONG)protocol
    );

    if (NT_SUCCESS(Status))
    {
        int sockfd = TO_SOCKETFD(KsIndex++);

        KsArray[FROM_SOCKETFD(sockfd)] = Socket;

        return sockfd;
    }

    return -1;
}

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    UNREFERENCED_PARAMETER(addrlen);

    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    Status = KsConnect(Socket, (PSOCKADDR)addr);

    return NT_SUCCESS(Status)
        ? 0
        : -1;
}

int listen(int sockfd, int backlog)
{
    UNREFERENCED_PARAMETER(sockfd);
    UNREFERENCED_PARAMETER(backlog);
    return 0;
}

int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    UNREFERENCED_PARAMETER(addrlen);

    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    Status = KsBind(Socket, (PSOCKADDR)addr);

    return NT_SUCCESS(Status)
        ? 0
        : -1;
}

int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    PKSOCKET NewSocket;
    Status = KsAccept(Socket, &NewSocket, NULL, (PSOCKADDR)addr);
    *addrlen = sizeof(SOCKADDR);

    if (NT_SUCCESS(Status))
    {
        int newsockfd = TO_SOCKETFD(KsIndex++);

        KsArray[FROM_SOCKETFD(newsockfd)] = NewSocket;

        return newsockfd;
    }

    return -1;
}

int send(int sockfd, const void* buf, size_t len, int flags)
{
    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    ULONG Length = (ULONG)len;
    Status = KsSend(Socket, (PVOID)buf, &Length, (ULONG)flags);

    return NT_SUCCESS(Status)
        ? (int)Length
        : -1;
}

int sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    UNREFERENCED_PARAMETER(addrlen);

    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    ULONG Length = (ULONG)len;
    Status = KsSendTo(Socket, (PVOID)buf, &Length, (ULONG)flags, (PSOCKADDR)dest_addr);

    return NT_SUCCESS(Status)
        ? (int)Length
        : -1;
}

int recv(int sockfd, void* buf, size_t len, int flags)
{
    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    ULONG Length = (ULONG)len;
    Status = KsRecv(Socket, (PVOID)buf, &Length, (ULONG)flags);

    return NT_SUCCESS(Status)
        ? (int)Length
        : -1;
}

int recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
{
    UNREFERENCED_PARAMETER(addrlen);

    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    ULONG Length = (ULONG)len;
    Status = KsSendTo(Socket, (PVOID)buf, &Length, (ULONG)flags, (PSOCKADDR)src_addr);
    *addrlen = sizeof(SOCKADDR);

    return NT_SUCCESS(Status)
        ? (int)Length
        : -1;
}

int closesocket(int sockfd)
{
    NTSTATUS Status;
    PKSOCKET Socket = KsArray[FROM_SOCKETFD(sockfd)];

    Status = KsCloseSocket(Socket);

    KsArray[FROM_SOCKETFD(sockfd)] = NULL;

    return NT_SUCCESS(Status)
        ? 0
        : -1;
}


void kinit_socket()
{
    NTSTATUS Status;

    //
    // Register as a WSK client.
    //

    WSK_CLIENT_NPI WskClient;
    WskClient.ClientContext = NULL;
    WskClient.Dispatch = &WskDispatch1;

    Status = WskRegister(&WskClient, &WskRegistration);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    //
    // Capture the provider NPI.
    //

    return WskCaptureProviderNPI(
        &WskRegistration,
        WSK_INFINITE_WAIT,
        &WskProvider
    );
}

void kcreate_socket()
{
    int result;

    char send_buffer[] = "Hello from WSK!";
    char recv_buffer[1024] = { 0 };

    int server_sockfd = socket_listen(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;//htons(9095);

    result = bind(server_sockfd, (struct sockaddr*)&addr, sizeof(addr));
    result = listen(server_sockfd, 1);

    socklen_t addrlen = sizeof(addr);
    int client_sockfd = accept(server_sockfd, (struct sockaddr*)&addr, &addrlen);

    result = recv(client_sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0);
    recv_buffer[sizeof(recv_buffer) - 1] = '\0';

    //DebuggerPrint("TCP server:\n%s\n", recv_buffer);

    result = send(client_sockfd, send_buffer, sizeof(send_buffer), 0);

    closesocket(client_sockfd);
    closesocket(server_sockfd);
}