#include <iostream>
#include <Windows.h>
#include <unordered_map>
#include "MinHook.h"

std::unordered_map<uint32_t, std::string> iid2Name;
std::unordered_map<uint32_t, std::string> id2Name;

// DbgPrintf
void DbgPrintf(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), format, args);
	OutputDebugStringA(buffer);
	va_end(args);
}

EXTERN_C void Func();
EXTERN_C void Report(uintptr_t index, uintptr_t id, uintptr_t iid, uintptr_t d)
{
	//std::cout << "COM函数被调用[" << id2Name[id] << ":" << iid2Name[iid] << "]: 函数索引：" << index << "，ClassID：" << std::uppercase << std::hex << id << "，" << "IID：" << std::hex << iid << std::endl;
}

std::string CLSIDToStringA(REFCLSID clsid)
{
	LPOLESTR wszClsid = nullptr;
	if (FAILED(StringFromCLSID(clsid, &wszClsid))) return "";

	// 转为 ANSI
	char szClsid[128] = {};
	WideCharToMultiByte(CP_ACP, 0, wszClsid, -1, szClsid, sizeof(szClsid), nullptr, nullptr);
	CoTaskMemFree(wszClsid);

	return szClsid;
}

std::string GetProgIDFromCLSID_A(REFCLSID clsid)
{
	std::string clsidStr = CLSIDToStringA(clsid);
	if (clsidStr.empty()) return "";

	std::string keyPath = "CLSID\\" + clsidStr;

	HKEY hKey = nullptr;
	char progID[256] = {};
	DWORD size = sizeof(progID);
	std::string result;

	if (RegOpenKeyExA(HKEY_CLASSES_ROOT, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hKey, nullptr, nullptr, nullptr, (LPBYTE)progID, &size) == ERROR_SUCCESS)
		{
			result = progID;
		}
		RegCloseKey(hKey);
	}

	return result;
}

std::string IIDToStringA(REFIID iid)
{
	LPOLESTR wszIID = nullptr;
	if (StringFromIID(iid, &wszIID) != S_OK)
		return "";

	char szIID[128] = {};
	WideCharToMultiByte(CP_ACP, 0, wszIID, -1, szIID, sizeof(szIID), nullptr, nullptr);
	CoTaskMemFree(wszIID);
	return std::string(szIID);
}

std::string GetInterfaceNameFromIID_A(REFIID iid)
{
	std::string iidStr = IIDToStringA(iid);
	if (iidStr.empty()) return "";

	std::string keyPath = "Interface\\" + iidStr;

	HKEY hKey = nullptr;
	char name[256] = {};
	DWORD size = sizeof(name);
	std::string result;

	if (RegOpenKeyExA(HKEY_CLASSES_ROOT, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hKey, nullptr, nullptr, nullptr, (LPBYTE)name, &size) == ERROR_SUCCESS)
		{
			result = name;
		}
		RegCloseKey(hKey);
	}

	return result;
}

decltype(&CoCreateInstance) OriginalCoCreateInstance = nullptr;
HRESULT WINAPI MyCoCreateInstance(_In_ REFCLSID rclsid, _In_opt_ LPUNKNOWN pUnkOuter, _In_ DWORD dwClsContext, _In_ REFIID riid, _COM_Outptr_ _At_(*ppv, _Post_readable_size_(_Inexpressible_(varies))) LPVOID  FAR* ppv)
{
	HRESULT result = OriginalCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

	std::string className = GetProgIDFromCLSID_A(rclsid);

	id2Name[rclsid.Data1] = className;
	iid2Name[riid.Data1] = GetInterfaceNameFromIID_A(riid);
	DbgPrintf("Com实例创建 className:%s id:%X iid:%X \n", className.c_str(), rclsid.Data1, riid.Data1, ppv);

	// 如果成功创建
	if (ppv && result == S_OK)
	{
		uintptr_t* vtable = **(uintptr_t***)ppv;

		// 填充新的vtable
		int funcCount = 0;
		while (vtable[funcCount]) { funcCount++; }
		uintptr_t* newVtable = new uintptr_t[funcCount]();

		uintptr_t funcAddr = (uintptr_t)Func;
		if (*(BYTE*)funcAddr == 0xE9)
		{
			// 获取真正函数地址
			funcAddr = *(int*)((uintptr_t)Func + 1) + (uintptr_t)Func + 5;
		}

		for (size_t i = 0; i < funcCount; i++)
		{
			if (vtable[i] == NULL) break;

			BYTE* funcBytes = new BYTE[0x1000];
			memcpy_s(funcBytes, 0x1000, (void*)funcAddr, 0x1000);
			*(uintptr_t*)&funcBytes[0x4A] = (uintptr_t)vtable[i];	// 函数的返回地址偏移量

			*(uint64_t*)&funcBytes[0xC] = i;						// 0xD 是index
			*(uint64_t*)&funcBytes[0xC + 10] = rclsid.Data1;		// ID
			*(uint64_t*)&funcBytes[0xC + 10 + 10] = riid.Data1;		// IID

			// 修改为可执行
			DWORD oldProtect;
			VirtualProtect(funcBytes, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);

			// 替换函数
			newVtable[i] = (uintptr_t)funcBytes;
		}

		// 替换vtable
		**(uintptr_t***)ppv = newVtable;
	}

	return result;
}

static DWORD Main(LPVOID)
{
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK)
	{
		DbgPrintf("HOOK初始化失败: %d\n", MH_StatusToString(status));
		return 1;
	}

	status = MH_CreateHookApi(L"Ole32.dll", "CoCreateInstance", MyCoCreateInstance, (LPVOID*)&OriginalCoCreateInstance);
	if (status != MH_OK)
	{
		DbgPrintf("HOOK创建失败: %d\n", MH_StatusToString(status));
		return 1;
	}

	status = MH_EnableHook(MH_ALL_HOOKS);
	if (status != MH_OK)
	{
		DbgPrintf("HOOK开启失败: %d\n", MH_StatusToString(status));
		return 1;
	}

	DbgPrintf("HOOK成功\n");

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, 0, Main, NULL, 0, NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

