#include <iostream>
#include <Windows.h>
#include "MinHook.h"

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

extern "C" uintptr_t originalShow = 0;

EXTERN_C void Func();
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

decltype(&CoCreateInstance) OriginalCoCreateInstance = nullptr;
HRESULT WINAPI MyCoCreateInstance(
	_In_ REFCLSID rclsid,
	_In_opt_ LPUNKNOWN pUnkOuter,
	_In_ DWORD dwClsContext,
	_In_ REFIID riid,
	_COM_Outptr_ _At_(*ppv, _Post_readable_size_(_Inexpressible_(varies))) LPVOID  FAR* ppv
)
{
	HRESULT result = OriginalCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

	std::string name = GetProgIDFromCLSID_A(rclsid);
	DbgPrintf("Com实例创建 name:%s id:%X iid:%X \n", name.c_str(), rclsid.Data1, riid.Data1, ppv);

	if (ppv && 0xDC1C5A9C == rclsid.Data1)
	{
		uintptr_t* vtable = **(uintptr_t***)ppv;
		//vtable[5] = (uintptr_t)show;

		originalShow = vtable[3];
		DWORD oldProtect;
		VirtualProtect(&vtable[3], sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);

		uintptr_t addr = (uintptr_t)Func;
		WriteProcessMemory(GetCurrentProcess(), &vtable[3], &addr, sizeof(uintptr_t), NULL);

		VirtualProtect(&vtable[3], sizeof(uintptr_t), oldProtect, &oldProtect);
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

