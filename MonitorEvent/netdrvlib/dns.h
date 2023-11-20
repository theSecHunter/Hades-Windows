#pragma once
#include <string>

// dns struct
#pragma pack(1)

typedef struct {
	unsigned short id;
	unsigned short flags;
	unsigned short quests;
	unsigned short answers;
	unsigned short author;
	unsigned short addition;
} dns_header, * p_dns_header;

typedef struct {
	unsigned char* name;
	unsigned short type;
	unsigned short classes;
} dns_query, * p_dns_query;

typedef struct {
	unsigned short name;
	unsigned short type;
	unsigned short classes;
	unsigned int ttl;
	unsigned short length;
	unsigned int addr;
} dns_response, * p_dns_response;

#pragma pack()

// dns analyze 
void DoHost(const char* buf, int len);
char* const conver_host(char* input_host);
char* const GetQueryHost(const char* szQueryPacket, int nQueryPacketLen);
const bool GetpHostName(const char* buf, const int len, std::string& pHost);