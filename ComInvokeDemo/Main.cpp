#include <windows.h>
#include <shobjidl.h>  // IFileOpenDialog
#include <iostream>

int main() {
	_wsetlocale(LC_ALL, L"chs");  // ����Ϊ������������

	// ���� DLL
	LoadLibraryA("ComMonitorDll.dll");

	system("pause");

	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		std::cerr << "COM ��ʼ��ʧ��" << std::endl;
		return 1;
	}

	IFileSaveDialog* pFileOpen = nullptr;

	// ���� IFileOpenDialog ʵ��
	hr = CoCreateInstance(CLSID_FileSaveDialog, NULL, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&pFileOpen));

	if (SUCCEEDED(hr)) {
		// ��ʾ�Ի���
		hr = pFileOpen->Show(NULL);
		if (SUCCEEDED(hr)) {
			// �û�ѡ�����ļ�����ȡ���
			IShellItem* pItem = nullptr;
			hr = pFileOpen->GetResult(&pItem);
			if (SUCCEEDED(hr)) {
				PWSTR pszFilePath = nullptr;
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

				if (SUCCEEDED(hr)) {
					std::wcout << L"��ѡ����ļ���: " << pszFilePath << std::endl;
					CoTaskMemFree(pszFilePath);
				}

				pItem->Release();
			}
		}
		else {
			std::cout << "�û�ȡ����Ի������" << std::endl;
		}

		pFileOpen->Release();
	}
	else {
		std::cerr << "���� IFileOpenDialog ʧ�ܡ�" << std::endl;
	}

	CoUninitialize();
	return 0;
}
