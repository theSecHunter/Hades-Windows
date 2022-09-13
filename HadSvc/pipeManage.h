#pragma once
#include <functional>

#define PIPE_BUFSIZE		40960

typedef std::function<void(const std::string&)>	DealFunc;
// 管道客户端结构
typedef struct _PIPECLIENT {
	std::string			name;		// 管道名字
	HANDLE				thread;		// 读线程
	HANDLE				handle;		// 管道
	BOOL				exit;		// 是否退出
	BOOL				connect;	// 是否已经连接
	DealFunc			dealFunc;	// 处理函数
	LIST_ENTRY          link;		// 客户端链表
}PIPECLIENT, * PPIPECLIENT;

// 管道服务器结构
typedef struct _PIPESERVER {
	std::string			name;		//  管道名字
	HANDLE				thread;		//	监听线程
	PIPECLIENT			client;		//	管道链表
	BOOL				exit;		//	是否退出
	DealFunc			dealFunc;	//  处理函数
	LIST_ENTRY          link;		//	服务器链表
}PIPESERVER, * PPIPESERVER;

void	InitializeList(PLIST_ENTRY ListHead);
bool	IsListEmpty(PLIST_ENTRY ListHead);
void	InsertList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry);
void	RemoveEntry(PLIST_ENTRY Entry);

// 获取列表末尾结构体
PPIPESERVER	GetTailSERVER(PLIST_ENTRY ListHead);
PPIPECLIENT	GetTailCLIENT(PLIST_ENTRY ListHead);

// 查找结构体
PPIPECLIENT FindCLIENT(const std::string& name, PLIST_ENTRY ListHead);
PPIPESERVER FindSERVER(const std::string& name, PLIST_ENTRY ListHead);

class PipeManage
{
public:
	static PipeManage* Instance();
	static void Uninstance();

private:
	PipeManage();
	~PipeManage();

public:
	bool ServerStart(const std::string& name, DealFunc dealFunc = nullptr);

	void ServerStop();

	bool ServerSend(const std::string& name, const std::string& str);

private:
	bool PipeTest(const std::string& name);

private:
	// 服务器N对多结构
	PIPESERVER	m_serverHead;

	// 关闭加个锁
	CRITICAL_SECTION m_cs;
};