#include <sysinfo.h>
#include "pipeManage.h"
#include <mutex>

static PipeManage* g_PipeManage = NULL;
static std::once_flag utilpipemanageoc;

PipeManage* PipeManage::Instance()
{
	std::call_once(utilpipemanageoc, [&] { g_PipeManage = new PipeManage(); });
	return g_PipeManage;
}

void PipeManage::Uninstance()
{
	delete g_PipeManage;
	g_PipeManage = NULL;
}

PipeManage::PipeManage()
{
	InitializeCriticalSection(&m_cs);

	InitializeList(&m_serverHead.link);
	InitializeList(&m_serverHead.client.link);
}

PipeManage::~PipeManage()
{
	DeleteCriticalSection(&m_cs);
}

// �������������߳�
DWORD WINAPI ReadThread(LPVOID param) {
	PPIPECLIENT client = (PPIPECLIENT)param;
	if (!client)
		return 0;

	while (!client->exit) {
		DWORD dwRead = 0;
		char buffer[PIPE_BUFSIZE] = { 0 };

		OVERLAPPED ovlp = { 0 };
		ovlp.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (ovlp.hEvent == 0) {
			break;
		}

		ReadFile(client->handle, buffer, PIPE_BUFSIZE, &dwRead, &ovlp);

		DWORD wait = WaitForSingleObject(ovlp.hEvent, INFINITE);
		if (wait != WAIT_OBJECT_0) {
			break;
		}

		dwRead = ovlp.InternalHigh;

		// �ر�
		if (dwRead == 0) {
			break;
		}

		std::string recvbuf(buffer, dwRead);

		if (client->dealFunc) {
			client->dealFunc(recvbuf);
		}
	}

	return 0;
}

// �����������̣߳��ȴ��ͻ�������
DWORD WINAPI ListenThread(LPVOID param) {
	PPIPESERVER server = (PPIPESERVER)param;

	// �Ƿ��˳�
	while (!server->exit) {
		// �����¿ͻ��˲��ȴ�����
		HANDLE handle = CreateNamedPipeA(server->name.c_str(),
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES, PIPE_BUFSIZE, PIPE_BUFSIZE, 0, NULL);

		// ����
		if (INVALID_HANDLE_VALUE == handle) {
			break;
		}

		// ����PIPE�ṹ��
		PPIPECLIENT client = new PIPECLIENT();
		client->handle = handle;
		client->exit = false;
		client->name = server->name;
		client->connect = false;
		client->dealFunc = server->dealFunc;

		// ����������б�
		InsertList(&server->client.link, &client->link);

		// �ȴ��ͻ�������
		if (!ConnectNamedPipe(handle, NULL)) {
			break;
		}

		client->connect = true;

		// �����ܵ����߳�,�������߳�����������¿ͻ��˲��ȴ�����
		client->thread = CreateThread(0, 0, ReadThread, client, 0, 0);
	}

	return 0;
}

bool PipeManage::ServerStart(const std::string& name, DealFunc dealFunc)
{
	EnterCriticalSection(&m_cs);

	// ������������߳�
	PPIPESERVER server = new PIPESERVER();
	server->name = name;
	server->exit = false;
	server->dealFunc = dealFunc;

	// ��ʼ���ͻ�������
	InitializeList(&server->client.link);

	// ����������б�
	InsertList(&m_serverHead.link, &server->link);

	// ���������߳�
	server->thread = CreateThread(0, 0, ListenThread, server, 0, 0);

	LeaveCriticalSection(&m_cs);
	return true;
}

void PipeManage::ServerStop() 
{
	EnterCriticalSection(&m_cs);

	// ֹͣ���з������߳�
	while (!IsListEmpty(&m_serverHead.link)) {
		PPIPESERVER	server = GetTailSERVER(&m_serverHead.link);

		// �����߳��˳�����
		server->exit = true;

		// �رո��߳������пͻ���
		while (!IsListEmpty(&server->client.link)) {
			PPIPECLIENT client = GetTailCLIENT(&server->client.link);

			// ���ÿͻ����˳�����
			client->exit = true;

			// �رտͻ��˹ܵ�
			DisconnectNamedPipe(client->handle);
			CloseHandle(client->handle);

			// �ȴ��ͻ����߳̽���
			WaitForSingleObject(client->thread, 3000);

			// �ӷ������б���ɾ������ͻ���
			RemoveEntry(&client->link);
			delete client;
		}

		// �ȴ��������̴߳������
		WaitForSingleObject(server->thread, 3000);
		CloseHandle(server->thread);

		// �ӷ������б���ɾ��
		RemoveEntry(&server->link);
		delete server;
	}

	LeaveCriticalSection(&m_cs);
}

bool PipeManage::ServerSend(const std::string& name, const std::string& str)
{
	PPIPESERVER server = FindSERVER(name, &m_serverHead.link);
	if (server == NULL) {
		return false;
	}

	// �Ը�ͨ���ϵ����пͻ��˶�����
	PLIST_ENTRY _EX_Blink = server->client.link.Blink;

	if (_EX_Blink == &server->client.link) {
		return false;
	}

	while (_EX_Blink != &server->client.link) {
		PPIPECLIENT client = CONTAINING_RECORD(_EX_Blink, PIPECLIENT, link);

		if (!client->connect) {
			_EX_Blink = _EX_Blink->Blink;
			continue;
		}

		DWORD dwWrite = 0;
		WriteFile(client->handle, str.c_str(), str.size(), &dwWrite, NULL);
		if (dwWrite == str.size()) {
			//LOG(INFO) << "proxy_client.exe ServerSend:" << StringConvert::ANSIToUnicode(str);
		}
		else {
			OutputDebugString(L"[HadesSvc] proxy_client.exe ServerSend Error");
		}

		_EX_Blink = _EX_Blink->Blink;
	}

	return true;
}

bool PipeManage::PipeTest(const std::string& name)
{
	BOOL bRet = WaitNamedPipeA(name.c_str(), NMPWAIT_WAIT_FOREVER);
	if (!bRet) {
		return false;
	}

	return true;
}

void InitializeList(PLIST_ENTRY ListHead)
{
	ListHead->Flink = ListHead->Blink = ListHead;
}

bool IsListEmpty(PLIST_ENTRY ListHead)
{
	return ListHead->Flink == ListHead;
}

void InsertList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
	PLIST_ENTRY _EX_Blink;
	PLIST_ENTRY _EX_ListHead;
	_EX_ListHead = ListHead;
	_EX_Blink = _EX_ListHead->Blink;
	Entry->Flink = _EX_ListHead;
	Entry->Blink = _EX_Blink;
	_EX_Blink->Flink = Entry;
	_EX_ListHead->Blink = Entry;
}

void RemoveEntry(PLIST_ENTRY Entry)
{
	PLIST_ENTRY _EX_Blink;
	PLIST_ENTRY _EX_Flink;
	_EX_Flink = Entry->Flink;
	_EX_Blink = Entry->Blink;
	_EX_Blink->Flink = _EX_Flink;
	_EX_Flink->Blink = _EX_Blink;
}

PPIPESERVER GetTailSERVER(PLIST_ENTRY ListHead)
{
	PPIPESERVER entry = CONTAINING_RECORD(ListHead->Blink, PIPESERVER, link);
	return entry;
}

PPIPECLIENT GetTailCLIENT(PLIST_ENTRY ListHead)
{
	PPIPECLIENT entry = CONTAINING_RECORD(ListHead->Blink, PIPECLIENT, link);
	return entry;
}

PPIPECLIENT FindCLIENT(const std::string& name, PLIST_ENTRY ListHead)
{
	PLIST_ENTRY _EX_Blink = ListHead->Blink;

	if (_EX_Blink == ListHead) {
		return NULL;
	}

	while (_EX_Blink != ListHead) {
		PPIPECLIENT client = CONTAINING_RECORD(_EX_Blink, PIPECLIENT, link);
		if (client->name == name) {
			return client;
		}
		_EX_Blink = _EX_Blink->Blink;
	}

	return NULL;
}

PPIPESERVER FindSERVER(const std::string& name, PLIST_ENTRY ListHead)
{
	PLIST_ENTRY _EX_Blink = ListHead->Blink;

	if (_EX_Blink == ListHead) {
		return NULL;
	}

	while (_EX_Blink != ListHead) {
		PPIPESERVER server = CONTAINING_RECORD(_EX_Blink, PIPESERVER, link);
		if (server->name == name) {
			return server;
		}
		_EX_Blink = _EX_Blink->Blink;
	}

	return NULL;
}
