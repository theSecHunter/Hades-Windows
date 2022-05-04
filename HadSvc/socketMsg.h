#pragma once
#include <winsock.h>

class socketMsg
{
public:
	socketMsg();
	~socketMsg();

	bool sendDlgMsg(const int msgid, char* info, const int lens);
	bool connect();
	bool send(const int msgid);
	bool send(const int msgid, char* buffer, const int buflen);
	bool sendto();
	const int recv();
	bool recvto();
	bool close();

protected:
	SOCKET m_socket = 0;
};

