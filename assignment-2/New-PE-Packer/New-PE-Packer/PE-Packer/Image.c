#include "Image.h"
#include <stdio.h>
#include <assert.h>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

/*
 - 描述
    将额外数据保存至文件
 - 输入参数
    hFile: 文件句柄
    lpImageInfo: PE映像信息
 - 返回值
    保存成功, 返回true; 否则为false
*/
static bool WriteExtDataToFile(_In_ HANDLE hFile, _In_ const PE_IMAGE_INFO *lpImageInfo);


/*
    判断文件是否为PE结构
*/
bool IsPeFile(_In_ const BYTE *lpFileBase)
{
    assert(lpFileBase != NULL);

    // 检查"MZ"字段
    const IMAGE_NT_HEADERS *lpNtHeader = ImageNtHeader((void*)lpFileBase);
    if (lpNtHeader == NULL)
    {
        return false;
    }

    // 检查"PE"字段
    if (lpNtHeader->Signature != IMAGE_NT_SIGNATURE
        || lpNtHeader->FileHeader.NumberOfSections <= 1)
    {
        return false;
    }

    return true;
}

/*
    将PE文件映射至内存
*/
void LoadPeImage(_In_reads_bytes_(dwFileSize) const BYTE *lpFileBase, 
    _In_ DWORD dwFileSize, _Out_ PE_IMAGE_INFO *lpImageInfo)
{
    assert(lpFileBase != NULL);
    assert(lpImageInfo != NULL);

    ZeroMemory(lpImageInfo, sizeof(PE_IMAGE_INFO));

    // 获取映像大小并申请内存空间
    const IMAGE_NT_HEADERS *lpNtHeader = ImageNtHeader((void*)lpFileBase);
    lpImageInfo->dwImageSize = lpNtHeader->OptionalHeader.SizeOfImage;
    lpImageInfo->lpImageBase = (BYTE*)VirtualAlloc(NULL, lpImageInfo->dwImageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    // 拷贝文件头
    DWORD dwDosHeaderSize = 0, dwNtHeaderSize = 0;
    DWORD dwHeadersSize = CalcHeadersSize(lpFileBase, &dwDosHeaderSize, &dwNtHeaderSize);
    CopyMemory(lpImageInfo->lpImageBase, lpFileBase, dwHeadersSize);

    lpImageInfo->lpNtHeader = (IMAGE_NT_HEADERS*)(lpImageInfo->lpImageBase + dwDosHeaderSize);
    lpImageInfo->lpSecHeader = (IMAGE_SECTION_HEADER*)(lpImageInfo->lpImageBase + dwDosHeaderSize + dwNtHeaderSize);
    
    // 映射节区数据
    WORD wSecNum = lpNtHeader->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER *lpSecHeader = (IMAGE_SECTION_HEADER*)(
        lpFileBase + ((BYTE*)lpImageInfo->lpSecHeader - lpImageInfo->lpImageBase));
    for (WORD i = 0; i != wSecNum; ++i)
    {
        const BYTE *lpCopySrc = lpFileBase + lpSecHeader[i].PointerToRawData;
        BYTE *lpCopyDest = lpImageInfo->lpImageBase + lpSecHeader[i].VirtualAddress;
        CopyMemory(lpCopyDest, lpCopySrc, lpSecHeader[i].SizeOfRawData);
    }
    
    // 检查并保存附加数据
    const BYTE *lpLastSecEnd = lpFileBase 
        + lpSecHeader[wSecNum - 1].PointerToRawData + lpSecHeader[wSecNum - 1].SizeOfRawData;
    lpImageInfo->dwExtDataSize = dwFileSize - (lpLastSecEnd - lpFileBase);
    if (lpImageInfo->dwExtDataSize > 0)
    {
        lpImageInfo->lpExtData = (BYTE*)VirtualAlloc(NULL,
            lpImageInfo->dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        CopyMemory(lpImageInfo->lpExtData, lpLastSecEnd, lpImageInfo->dwExtDataSize);
    }
    else
    {
        lpImageInfo->lpExtData = NULL;
    }
}

/*
    释放PE映像内存
*/
bool FreePeImage(_Inout_ PE_IMAGE_INFO *lpImageInfo)
{
    assert(lpImageInfo != NULL);

    bool IsSuccess = false;
    if (lpImageInfo->lpImageBase != NULL)
    {
        VirtualFree(lpImageInfo->lpImageBase, 0, MEM_RELEASE);
        IsSuccess = true;
    }

    if (lpImageInfo->lpExtData != NULL)
    {
        VirtualFree(lpImageInfo->lpExtData, 0, MEM_RELEASE);
    }

    ZeroMemory(lpImageInfo, sizeof(PE_IMAGE_INFO));
    return IsSuccess;
}

/*
    将PE映像保存至文件
*/
bool WriteImageToFile(_In_z_ const wchar_t *lpFileName,
    _In_ const PE_IMAGE_INFO *lpImageInfo, _Out_opt_ DWORD *lpFileSize)
{
    assert(lpFileName != NULL);
    assert(lpImageInfo != NULL);

    bool IsSuccess = false;
    HANDLE hFile = CreateFileW(lpFileName, GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        goto _Exit;
    }
    
    // 保存PE文件头
    DWORD dwWrittenSize = 0;
    DWORD dwFileAlign = lpImageInfo->lpNtHeader->OptionalHeader.FileAlignment;
    DWORD dwHeadersSize = AlignSize(CalcHeadersSize(lpImageInfo->lpImageBase, NULL, NULL), dwFileAlign);
    if (WriteFile(hFile, lpImageInfo->lpImageBase, dwHeadersSize, &dwWrittenSize, NULL) == FALSE)
    {
        goto _Exit;
    }
    
    // 保存节区数据
    WORD wSecNum = lpImageInfo->lpNtHeader->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER *lpSecHeader = lpImageInfo->lpSecHeader;
    for (WORD i = 0; i != wSecNum; ++i)
    {
        DWORD dwRawSize = lpSecHeader[i].SizeOfRawData;
        DWORD dwRva = lpSecHeader[i].VirtualAddress;
        const BYTE *lpData = lpImageInfo->lpImageBase + dwRva;
        if (WriteFile(hFile, lpData, dwRawSize, &dwWrittenSize, NULL) == FALSE)
        {
            goto _Exit;
        }
    }
    
    // 保存附加数据
    if (WriteExtDataToFile(hFile, lpImageInfo) == false)
    {
        goto _Exit;
    }

    if (lpFileSize != NULL)
    {
        *lpFileSize = GetFileSize(hFile, NULL);
    }

    IsSuccess = true;

_Exit:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = NULL;
    }

    return IsSuccess;
}

/*
    将相对虚拟地址(RVA)转换为虚拟地址(VA)
*/
BYTE *RvaToVa(_In_ BYTE *lpImageBase, _In_ DWORD dwRva)
{
    return lpImageBase + dwRva;
}

/*
    计算对齐后的数据大小
*/
DWORD AlignSize(_In_ DWORD dwSize, _In_ DWORD dwAlign)
{
    return ((dwSize + dwAlign - 1) / dwAlign * dwAlign);
}

/*
    将附加数据保存至文件
*/
bool WriteExtDataToFile(_In_ HANDLE hFile, _In_ const PE_IMAGE_INFO *lpImageInfo)
{
    assert(lpImageInfo != NULL);

    if (lpImageInfo->dwExtDataSize != 0 && lpImageInfo->lpExtData != NULL)
    {
        DWORD dwWrittenSize = 0;
        return (bool)WriteFile(hFile, lpImageInfo->lpExtData,
            lpImageInfo->dwExtDataSize, &dwWrittenSize, NULL);
    }
    else
    {
        return true;
    }
}

/*
    计算PE文件头大小
*/
DWORD CalcHeadersSize(_In_ const BYTE *lpFileBase, 
    _Out_opt_ DWORD *lpDosHeaderSize, _Out_opt_ DWORD *lpNtHeaderSize)
{
    assert(lpFileBase != NULL);

    // DOS头部可能包含自定义代码, 不能使用sizeof(IMAGE_DOS_HEADER)计算其大小
    DWORD dwDosHeaderSize = ((IMAGE_DOS_HEADER*)lpFileBase)->e_lfanew;
    if (lpDosHeaderSize != NULL)
    {
        *lpDosHeaderSize = dwDosHeaderSize;
    }

    // IMAGE_OPTIONAL_HEADER结构大小由IMAGE_FILE_HEADER::SizeOfOptionalHeader成员指定
    // 少数程序并不包含16个IMAGE_DATA_DIRECTORY项目
    const IMAGE_NT_HEADERS *lpNtHeader = ImageNtHeader((void*)lpFileBase);
    DWORD dwNtHeaderSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) 
        + lpNtHeader->FileHeader.SizeOfOptionalHeader;
    if (lpNtHeaderSize != NULL)
    {
        *lpNtHeaderSize = dwNtHeaderSize;
    }

    WORD wSecNum = lpNtHeader->FileHeader.NumberOfSections;
    DWORD dwSecHeaderSize = wSecNum * sizeof(IMAGE_SECTION_HEADER);

    return dwDosHeaderSize + dwNtHeaderSize + dwSecHeaderSize;
}