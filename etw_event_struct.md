#### ETW文档

**propName是回调第二个参数PTRACE_EVENT_INFO info如下：**

```c
for(..........)
{
        auto& pi = info->EventPropertyInfoArray[i];
        propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
}
```

##### Process

###### Guid

```c
{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}
```

###### 字段

```c
if (0 == lstrcmpW(propName.c_str(), L"UniqueProcessKey"))
else if (0 == lstrcmpW(propName.c_str(), L"ProcessId"))
else if (0 == lstrcmpW(propName.c_str(), L"ParentId"))
else if (0 == lstrcmpW(propName.c_str(), L"ExitStatus")) -- 259 start | 0 exit
else if (0 == lstrcmpW(propName.c_str(), L"DirectoryTableBase"))
else if (0 == lstrcmpW(propName.c_str(), L"Flags"))
else if (0 == lstrcmpW(propName.c_str(), L"UserSID"))
else if (0 == lstrcmpW(propName.c_str(), L"ImageFileName"))
else if (0 == lstrcmpW(propName.c_str(), L"CommandLine"))
else if (0 == lstrcmpW(propName.c_str(), L"PackageFullName"))
else if (0 == lstrcmpW(propName.c_str(), L"ApplicationId"))
```

##### NetWork

###### Guid

```
{9A280AC0-C8E0-11D1-84E2-00C04FB998A2} - TcpIp
{BF3A50C5-A9C9-4988-A005-2DF0B7C80F80} - UdpIp
```

###### 字段

```c
if (0 == lstrcmpW(propName.c_str(), L"PID"))
else if (0 == lstrcmpW(propName.c_str(), L"size"))
else if (0 == lstrcmpW(propName.c_str(), L"daddr"))
else if (0 == lstrcmpW(propName.c_str(), L"saddr"))
else if (0 == lstrcmpW(propName.c_str(), L"dport"))
else if (0 == lstrcmpW(propName.c_str(), L"sport"))
```

##### Thread

###### Guid

```
{3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}
```

###### 字段

```c
if (0 == lstrcmpW(propName.c_str(), L"ProcessId"))
else if (0 == lstrcmpW(propName.c_str(), L"TThreadId"))
else if (0 == lstrcmpW(propName.c_str(), L"StackBase"))
else if (0 == lstrcmpW(propName.c_str(), L"StackLimit"))
else if (0 == lstrcmpW(propName.c_str(), L"UserStackBase"))
else if (0 == lstrcmpW(propName.c_str(), L"UserStackLimit"))
else if (0 == lstrcmpW(propName.c_str(), L"Affinity"))
else if (0 == lstrcmpW(propName.c_str(), L"Win32StartAddr"))
else if (0 == lstrcmpW(propName.c_str(), L"TebBase"))
else if (0 == lstrcmpW(propName.c_str(), L"SubProcessTag"))
else if (0 == lstrcmpW(propName.c_str(), L"BasePriority"))
else if (0 == lstrcmpW(propName.c_str(), L"PagePriority"))
else if (0 == lstrcmpW(propName.c_str(), L"IoPriority"))
else if (0 == lstrcmpW(propName.c_str(), L"ThreadFlags"))
```

##### File

###### Guid

```
{90CBDC39-4A3E-11D1-84F4-0000F80464E3}
```

###### 字段

```c
if (0 == lstrcmpW(propName.c_str(), L"Offset"))
else if (0 == lstrcmpW(propName.c_str(), L"IrpPtr"))
else if (0 == lstrcmpW(propName.c_str(), L"FileObject"))
else if (0 == lstrcmpW(propName.c_str(), L"FileKey"))
else if (0 == lstrcmpW(propName.c_str(), L"TTID"))
else if (0 == lstrcmpW(propName.c_str(), L"IoSize"))
else if (0 == lstrcmpW(propName.c_str(), L"IoFlags"))
```

##### RegisterTab

###### Guid

```
{AE53722E-C863-11D2-8659-00C04FA321A1}
```

###### 字段

```c
if (0 == lstrcmpW(propName.c_str(), L"InitialTime"))
else if (0 == lstrcmpW(propName.c_str(), L"Status"))
else if (0 == lstrcmpW(propName.c_str(), L"Index"))
else if (0 == lstrcmpW(propName.c_str(), L"KeyHandle"))
else if (0 == lstrcmpW(propName.c_str(), L"KeyName"))
```

##### ImageMod

###### Guid

```
{2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}
```

###### 字段

```c
if (0 == lstrcmpW(propName.c_str(), L"ImageBase"))
else if (0 == lstrcmpW(propName.c_str(), L"ImageSize"))
else if (0 == lstrcmpW(propName.c_str(), L"ProcessId"))
else if (0 == lstrcmpW(propName.c_str(), L"ImageChecksum"))
else if (0 == lstrcmpW(propName.c_str(), L"TimeDateStamp"))
else if (0 == lstrcmpW(propName.c_str(), L"SignatureLevel"))
else if (0 == lstrcmpW(propName.c_str(), L"SignatureType"))
else if (0 == lstrcmpW(propName.c_str(), L"Reserved0"))
else if (0 == lstrcmpW(propName.c_str(), L"DefaultBase"))
else if (0 == lstrcmpW(propName.c_str(), L"Reserved1"))
else if (0 == lstrcmpW(propName.c_str(), L"Reserved2"))
else if (0 == lstrcmpW(propName.c_str(), L"Reserved3"))
else if (0 == lstrcmpW(propName.c_str(), L"Reserved4"))
else if (0 == lstrcmpW(propName.c_str(), L"FileName"))
```

##### SystemCall

详细代码：uetw.h/.cpp