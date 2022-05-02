//#pragma once
//#include "HlprIocpService.h"
//#include <WinSock2.h>
//#include <MSWSock.h>
//#include <mutex>
//#include <list>
//#include <vector>
//
////namespace TcpServer
////{
//
//	struct TCP_PACKET
//	{
//		TCP_PACKET()
//		{
//			buffer.len = 0;
//			buffer.buf = NULL;
//		}
//		TCP_PACKET(const char* buf, int len)
//		{
//			if (len > 0)
//			{
//				buffer.buf = new char[len];
//				buffer.len = len;
//
//				if (buf)
//				{
//					memcpy(buffer.buf, buf, len);
//				}
//			}
//			else
//			{
//				buffer.buf = NULL;
//				buffer.len = 0;
//			}
//		}
//
//		WSABUF& operator ()()
//		{
//			return buffer;
//		}
//
//		void free()
//		{
//			if (buffer.buf)
//			{
//				delete[] buffer.buf;
//			}
//		}
//
//		WSABUF	buffer;
//	};
//	typedef std::vector<TCP_PACKET> tPacketList;
//	enum OV_TYPE
//	{
//		OVT_ACCEPT,
//		OVT_CONNECT,
//		OVT_CLOSE,
//		OVT_SEND,
//		OVT_RECEIVE
//	};
//	struct OV_DATA
//	{
//		OV_DATA()
//		{
//			memset(&ol, 0, sizeof(ol));
//		}
//		~OV_DATA()
//		{
//			for (tPacketList::iterator it = packetList.begin(); it != packetList.end(); it++)
//			{
//				it->free();
//			}
//		}
//
//		OVERLAPPED	ol;
//		LIST_ENTRY	entry;
//		LIST_ENTRY	entryEventList;
//		ULONG64		id;
//		OV_TYPE		type;
//		tPacketList packetList;
//
//		SOCKET	socket;
//		DWORD	dwTransferred;
//		int		error;
//	};
//
//	enum PROXY_STATE
//	{
//		PS_NONE,
//		PS_CONNECTED,
//		PS_ERROR,
//		PS_CLOSED,
//	};
//
//	enum PROXY_TYPE
//	{
//		PROXY_NONE,
//		PROXY_SS
//	};
//
//	struct SOCKET_DATA
//	{
//		SOCKET_DATA()
//		{
//			socket = INVALID_SOCKET;
//			disconnected = false;
//			receiveInProgress = false;
//			sendInProgress = false;
//			disconnect = false;
//			closed = false;
//		}
//		~SOCKET_DATA()
//		{
//			if (socket != INVALID_SOCKET)
//			{
//				closesocket(socket);
//			}
//			for (tPacketList::iterator it = packetList.begin(); it != packetList.end(); it++)
//			{
//				it->free();
//			}
//		}
//
//		SOCKET	socket;
//		bool	disconnected;
//		bool	receiveInProgress;
//		bool	sendInProgress;
//		bool	disconnect;
//		bool	closed;
//		tPacketList packetList;
//	};
//
//	struct PROXY_DATA
//	{
//		PROXY_DATA()
//		{
//			id = 0;
//			proxyState = PS_NONE;
//			suspended = false;
//			offline = false;
//			//memset(&connInfo, 0, sizeof(connInfo));
//			refCount = 1;
//			proxyType = PROXY_NONE;
//			proxyAddressLen = 0;
//			jwtLen = 0;
//		}
//		~PROXY_DATA()
//		{
//		}
//
//		ULONG64 id;
//
//		SOCKET_DATA		inSocket;
//		SOCKET_DATA		outSocket;
//
//		PROXY_STATE		proxyState;
//		//NF_TCP_CONN_INFO connInfo;
//
//		PROXY_TYPE		proxyType;
//		char			proxyAddress[28];
//		int				proxyAddressLen;
//
//		bool	suspended;
//		bool	offline;
//
//		int		refCount;
//		std::mutex lock;
//
//		char jwtBuf[256];
//		DWORD jwtLen;
//
//	private:
//		PROXY_DATA& operator = (const PROXY_DATA& v)
//		{
//			return *this;
//		}
//
//	};
//
//	class HlprSocketTcp : public IOCPHandler
//	{
//	public:
//		HlprSocketTcp();
//		virtual ~HlprSocketTcp();
//
//		bool tcp_init(unsigned short port, bool bindToLocalhost, int threadCount);
//		bool tcp_free();
//		bool tcp_close();
//
//		bool InitExtensions();
//		void execute();
//		virtual void onComplete(SOCKET socket, DWORD dwTransferred, OVERLAPPED* pOverlapped, int error);
//
//	protected:
//		OV_DATA* newOV_DATA()
//		{
//			OV_DATA* pov = new OV_DATA();
//			m_cs.lock();
//			m_ovDataList.push_back(&pov->entry);
//			m_ovDataCounter++;
//			m_cs.unlock();
//			return pov;
//		}
//
//		void deleteOV_DATA(OV_DATA* pov)
//		{
//			m_cs.lock();
//			m_ovDataList.erase(std::remove(m_ovDataList.begin(), m_ovDataList.end(), &pov->entry), m_ovDataList.end());
//			delete pov;
//			m_ovDataCounter--;
//			m_cs.unlock();
//		}
//
//	private:
//		unsigned short		m_port;
//		HlprIocpService		m_IocpSvc;
//		SOCKET				m_listenSocket;
//		SOCKET				m_acceptSocket;
//		bool				m_ipv4Available;
//		bool				m_ipv6Available;
//
//		LPFN_ACCEPTEX		m_pAcceptEx;
//		LPFN_CONNECTEX		m_pConnectEx;
//		LPFN_GETACCEPTEXSOCKADDRS m_pGetAcceptExSockaddrs;
//
//		std::list<LIST_ENTRY*>  m_ovDataList;
//		int						m_ovDataCounter;
//		std::list<LIST_ENTRY*>	m_eventList;
//		std::mutex				m_csEventList;
//
//		std::mutex				m_cs;
//	};
////}
//
