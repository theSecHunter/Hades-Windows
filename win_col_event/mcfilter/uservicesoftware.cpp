#include <Windows.h>

// 获取服务
//void AllServicesCheck()
//{
//	PrintfLog("\n系统服务信息: \n");
//	do {
//		SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
//		if (SCMan == NULL) {
//			break;
//		}
//		LPENUM_SERVICE_STATUS service_status;
//		DWORD cbBytesNeeded = NULL;
//		DWORD ServicesReturned = NULL;
//		DWORD ResumeHandle = NULL;
//
//		service_status = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, MAX_SERVICE_SIZE);
//
//
//		BOOL ESS = EnumServicesStatus(SCMan,						// 句柄
//			SERVICE_WIN32,                                          // 服务类型
//			SERVICE_STATE_ALL,                                      // 服务的状态
//			(LPENUM_SERVICE_STATUS)service_status,                  // 输出参数，系统服务的结构
//			MAX_SERVICE_SIZE,                                       // 结构的大小
//			&cbBytesNeeded,                                         // 输出参数，接收返回所需的服务
//			&ServicesReturned,                                      // 输出参数，接收返回服务的数量
//			&ResumeHandle);                                         // 输入输出参数，第一次调用必须为0，返回为0代表成功
//		if (ESS == NULL) {
//			break;
//		}
//		for (int i = 0; i < static_cast<int>(ServicesReturned); i++) {
//			fwprintf(g_pFile, L"ServiceName: %s\t", service_status[i].lpDisplayName);
//			// std::cout << "ServiceName: " << service_status[i].lpDisplayName << "\t";
//			switch (service_status[i].ServiceStatus.dwCurrentState) { // 服务状态
//			case SERVICE_CONTINUE_PENDING:
//				PrintfLog("CONTINUE_PENDING\n");
//				break;
//			case SERVICE_PAUSE_PENDING:
//				PrintfLog("PAUSE_PENDING\n");
//				break;
//			case SERVICE_PAUSED:
//				PrintfLog("PAUSED\n");
//				break;
//			case SERVICE_RUNNING:
//				PrintfLog("RUNNING\n");
//				break;
//			case SERVICE_START_PENDING:
//				PrintfLog("START_PENDING\n");
//				break;
//			case SERVICE_STOPPED:
//				PrintfLog("STOPPED\n");
//				break;
//			default:
//				PrintfLog("UNKNOWN\n");
//				break;
//			}
//			LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;          // 服务详细信息结构
//			SC_HANDLE service_curren = NULL;                        // 当前的服务句柄
//			LPSERVICE_DESCRIPTION lpqscBuf2 = NULL;					// 服务描述信息
//			service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG);        // 打开当前服务
//			lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, MAX_QUERY_SIZE);                        // 分配内存， 最大为8kb 
//
//			if (NULL == QueryServiceConfig(service_curren, lpServiceConfig, MAX_QUERY_SIZE, &ResumeHandle)) {
//				break;
//			}
//			fwprintf(g_pFile, L"Path: %s\n", lpServiceConfig->lpBinaryPathName);
//			DWORD dwNeeded = 0;
//			if (QueryServiceConfig2(service_curren, SERVICE_CONFIG_DESCRIPTION, NULL, 0,
//				&dwNeeded) == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
//			{
//				lpqscBuf2 = (LPSERVICE_DESCRIPTION)LocalAlloc(LPTR, MAX_QUERY_SIZE);
//				if (QueryServiceConfig2(service_curren, SERVICE_CONFIG_DESCRIPTION,
//					(BYTE*)lpqscBuf2, dwNeeded, &dwNeeded))
//				{
//					fwprintf(g_pFile, L" Description: %s\n", lpqscBuf2->lpDescription);
//				}
//				LocalFree(lpqscBuf2);
//			}
//			CloseServiceHandle(service_curren);
//		}
//		CloseServiceHandle(SCMan);
//	} while (0);
//}