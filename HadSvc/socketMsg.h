#pragma once
class socketMsg
{
public:
	socketMsg();
	~socketMsg();

	bool connect();
	bool send();
	bool sendto();
	bool recv();
	bool recvto();
	bool close();
};

