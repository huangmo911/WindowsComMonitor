#include <windows.h>
#include <shobjidl.h>  // IFileOpenDialog
#include <iostream>

int main() {
	_wsetlocale(LC_ALL, L"chs");  // 设置为简体中文区域

	// 加载 DLL
	LoadLibraryA("ComMonitorDll.dll");

	system("pause");

	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		std::cerr << "COM 初始化失败" << std::endl;
		return 1;
	}

	IFileSaveDialog* pFileOpen = nullptr;

	// 创建 IFileOpenDialog 实例
	hr = CoCreateInstance(CLSID_FileSaveDialog, NULL, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&pFileOpen));

	if (SUCCEEDED(hr)) {
		// 显示对话框
		hr = pFileOpen->Show(NULL);
		if (SUCCEEDED(hr)) {
			// 用户选择了文件，获取结果
			IShellItem* pItem = nullptr;
			hr = pFileOpen->GetResult(&pItem);
			if (SUCCEEDED(hr)) {
				PWSTR pszFilePath = nullptr;
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

				if (SUCCEEDED(hr)) {
					std::wcout << L"你选择的文件是: " << pszFilePath << std::endl;
					CoTaskMemFree(pszFilePath);
				}

				pItem->Release();
			}
		}
		else {
			std::cout << "用户取消或对话框出错。" << std::endl;
		}

		pFileOpen->Release();
	}
	else {
		std::cerr << "创建 IFileOpenDialog 失败。" << std::endl;
	}

	CoUninitialize();
	return 0;
}
