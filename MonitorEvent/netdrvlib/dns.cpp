#include <Windows.h>
#include "dns.h"
#include <string>

const bool DecodeDotStr(const char* szEncodedStr, unsigned short* pusEncodedStrLen, char* szDotStr, unsigned short nDotStrSize, const char* szPacketStartPos)
{
	if (NULL == szEncodedStr ||
		NULL == pusEncodedStrLen ||
		NULL == szDotStr)
	{
		return false;
	}
	const char* pDecodePos = szEncodedStr;
	USHORT usPlainStrLen = 0;
	BYTE nLabelDataLen = 0;
	*pusEncodedStrLen = 0;
	while ((nLabelDataLen = *pDecodePos) != 0x00)
	{
		if ((nLabelDataLen & 0xc0) == 0)
		{
			if (usPlainStrLen + nLabelDataLen + 1 > nDotStrSize)
			{
				return false;
			}
			memcpy(szDotStr + usPlainStrLen, pDecodePos + 1, nLabelDataLen);
			memcpy(szDotStr + usPlainStrLen + nLabelDataLen, ".", 1);
			pDecodePos += (nLabelDataLen + 1);
			usPlainStrLen += (nLabelDataLen + 1);
			*pusEncodedStrLen += (nLabelDataLen + 1);
		}
		else
		{
			if (szPacketStartPos == NULL)
			{
				return false;
			}
			USHORT usJumpPos = ntohs(*(USHORT*)(pDecodePos)) & 0x3fff;
			USHORT nEncodeStrLen = 0;
			if (!DecodeDotStr(szPacketStartPos + usJumpPos, &nEncodeStrLen, szDotStr + usPlainStrLen, nDotStrSize - usPlainStrLen, szPacketStartPos))
			{
				return false;
			}
			else
			{
				*pusEncodedStrLen += 2;
				return true;
			}
		}
	}
	szDotStr[usPlainStrLen - 1] = '\0';
	*pusEncodedStrLen += 1;
	return true;
}

char* const conver_host(char* input_host)
{
	if (NULL == input_host)
	{
		return NULL;
	}

	char* output_string = NULL;
	char* host = input_host;
	unsigned short alloc_length = 0;
	while ('\0' != *host)
	{
		alloc_length += *(unsigned char*)host + 1;
		host = (char*)(input_host + alloc_length);
	}
	output_string = (char*)malloc(alloc_length);
	if (output_string)
	{
		RtlSecureZeroMemory(output_string, alloc_length);
		unsigned short read_point = 0;
		while ('\0' != *input_host)
		{
			unsigned char read_length = *input_host++;
			memcpy((char*)(output_string + read_point), input_host, read_length);
			*(char*)(output_string + read_point + read_length) = '.';
			read_point += read_length + 1;
			input_host += read_length;
		}
		*(char*)(output_string + read_point - 1) = '\0';
		return output_string;
	}
	return nullptr;
}

char* const GetQueryHost(const char* szQueryPacket, int nQueryPacketLen)
{
	char* pQueryHost = NULL;
	p_dns_header dns_ = (p_dns_header)szQueryPacket;
	p_dns_query query_ = (p_dns_query)&szQueryPacket[sizeof(dns_header)];
	unsigned short query_type = ntohs(*(unsigned short*)((unsigned long)query_ + strlen((const char*)query_) + 1));
	if (query_type == 1)
	{
		pQueryHost = conver_host((char*)query_);
	}
	return pQueryHost;
}

void DoHost(const char* buf, int len)
{
	try
	{
		dns_header* const head = (dns_header*)buf;
		if (!head)
			return;
		unsigned short quests = ntohs(head->quests);
		unsigned short answers = ntohs(head->answers);
		if ((ntohs(head->flags) & 0xfb7f) == 0x8100)
		{
			unsigned short nEncodedNameLen;
			char szDotName[260];
			char szDomain[260] = { 0 };
			const char* pDnsData = buf + sizeof(dns_header);
			bool bOK = true;
			for (int i = 0; i < quests; i++)
			{
				if (!DecodeDotStr(pDnsData, &nEncodedNameLen, szDotName, sizeof(szDotName), NULL))
				{
					bOK = false;
					break;
				}
				pDnsData += (nEncodedNameLen + 4);
			}
			if (bOK)
			{
				if (quests == 1)
				{
					lstrcpyA(szDomain, szDotName);
				}
				for (int i = 0; i < answers; i++)
				{
					if (!DecodeDotStr(pDnsData, &nEncodedNameLen, szDotName, sizeof(szDotName), buf))
					{
						break;
					}
					pDnsData += nEncodedNameLen;
					unsigned short nAnswerType = ntohs(*(unsigned short*)(pDnsData));
					unsigned short nAnswerDataLen = ntohs(*(unsigned short*)(pDnsData + 8));
					pDnsData += 10;
					if (nAnswerType == 1)
					{
						char* pDomain = szDomain[0] ? szDomain : szDotName;
						const DWORD dwIp = *(DWORD*)(pDnsData);
					}
					pDnsData += nAnswerDataLen;
				}
			}
		}
	}
	catch (...)
	{
	}
}

const bool GetpHostName(const char* buf, const int len, std::string& pHost)
{
	__try
	{
		char* pHost_ = GetQueryHost(buf, len);
		if (pHost_)
		{
			pHost = pHost_;
			::free(pHost_);
			pHost_ = nullptr;
			return true;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return false;
}