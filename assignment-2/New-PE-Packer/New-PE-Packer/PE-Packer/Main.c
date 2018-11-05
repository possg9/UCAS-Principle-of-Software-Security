#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include "Image.h"
#include "Import.h"
#include "Shell.h"
#include "Section.h"

// 只支持x86环境
#ifdef _WIN64
    #error Only For x86
#endif

int wmain(int argc, wchar_t *argv[])
{
    bool IsSuccess = false;
    HANDLE hFileMap = NULL;                     // 内存映射文件句柄
    const BYTE *lpFileBase = NULL;              // 内存映射文件地址
    BYTE *lpNewImpTab = NULL;                   // 变形后的导入表
    BYTE *lpEncryInfo = NULL;                   // 加密信息
    PE_IMAGE_INFO ImageInfo = { 0 };            // PE映像结构
    IMAGE_SECTION_HEADER NewSecHeader = { 0 };  // 外壳段的节区表项

	if (argc < 3)
		printf("Usage : PE-Packer.exe InputFileName OutputFileName\n");

    // 打开文件
    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        goto _Exit;
    }

    // 创建内存映射文件
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    hFileMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMap == NULL)
    {
        goto _Exit;
    }

    lpFileBase = (BYTE*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == NULL)
    {
        goto _Exit;
    }

    // 判断PE格式
    if (IsPeFile(lpFileBase) != true)
    {
        goto _Exit;
    }

    // 加载PE文件
    LoadPeImage(lpFileBase, dwFileSize, &ImageInfo);

    // 导入表变形
    DWORD dwNewImpTabSize = CalcNewImpTabSize(&ImageInfo);
    lpNewImpTab = (BYTE*)VirtualAlloc(NULL, dwNewImpTabSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    TransformImpTab(&ImageInfo, lpNewImpTab, dwNewImpTabSize);

    // 清空原始导入表
    ClearImpTab(&ImageInfo);

    // 加密节区数据
    DWORD dwEncryInfoSize = CalcEncryInfoSize(&ImageInfo);
    lpEncryInfo = (BYTE*)VirtualAlloc(NULL, dwEncryInfoSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    EncrySection(&ImageInfo, lpEncryInfo, dwEncryInfoSize);

    // 新增节区
    DWORD dwShellSize = CalcShellSize(dwNewImpTabSize);
    AppendSection(&ImageInfo, ".shell", dwShellSize, &NewSecHeader);

    // 安装外壳
    if (SetupShell(&ImageInfo, lpNewImpTab, dwNewImpTabSize, lpEncryInfo, dwEncryInfoSize) != true)
    {
        goto _Exit;
    }

    // 将PE映像保存至输出文件
    if (WriteImageToFile(argv[2], &ImageInfo, NULL) != true)
    {
        goto _Exit;
    }

    IsSuccess = true;

_Exit:
    if (IsSuccess != true)
    {
        DeleteFileW(argv[2]);
    }

	FreePeImage(&ImageInfo);

    if (lpFileBase != NULL)
    {
        UnmapViewOfFile(lpFileBase);
        lpFileBase = NULL;
    }

    if (lpNewImpTab != NULL)
    {
        VirtualFree(lpNewImpTab, 0, MEM_RELEASE);
        lpNewImpTab = NULL;
    }

    if (lpEncryInfo != NULL)
    {
        VirtualFree(lpEncryInfo, 0, MEM_RELEASE);
        lpEncryInfo = NULL;
    }

    if (hFileMap != NULL)
    {
        CloseHandle(hFileMap);
        hFileMap = NULL;
    }

    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }

    return EXIT_SUCCESS;
}