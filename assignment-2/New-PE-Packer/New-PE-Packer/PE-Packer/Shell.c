#include "Shell.h"
#include <assert.h>

#pragma warning(disable:4047)

/*
    保存外壳加密段的信息, 同AsmShell.asm中的定义相同
*/
typedef struct _INIT_DATA
{
    DWORD dwShellPackOffset;    // 数据偏移 (相对于外壳第一段基地址)
    DWORD dwShellPackSize;      // 数据大小
} INIT_DATA;

/*
    保存原始PE文件的相关信息, 同AsmShell.asm中的定义相同
*/
typedef struct _ORIGIN_DATA
{
    DWORD dwEntryPoint;         // 代码入口点
    DWORD dwImpTabOffset;       // 变形后的原导入表偏移 (相对于外壳第二段基地址)
    DWORD dwRelocTabRva;        // 重定位表RVA
    DWORD dwTlsTabRva;          // TLS表RVA
    DWORD dwImageBase;          // 原始映像基地址
    BYTE szSecEncryInfo[0xA0];  // 节区加密信息
} ORIGIN_DATA;

// AsmShell.asm中的导出数据, 用于地址定位及数据存储
extern DWORD Begin;                 // 外壳基地址
extern DWORD ImpTabBegin;           // 外壳导入表起始地址
extern DWORD ImpTabEnd;             // 外壳导入表结束地址
extern DWORD InitBegin;             // 外壳第一段(初始化段)起始地址
extern DWORD InitEnd;               // 外壳第一段(初始化段)结束地址
extern DWORD ShellBegin;            // 外壳第二段(核心段)起始地址
extern DWORD ShellEnd;              // 外壳第二段(核心段)结束地址
extern INIT_DATA InitData;          // 外壳中加密部分的信息
extern ORIGIN_DATA OriginData;      // 原始PE文件的相关信息

/*
 - 描述
    获取外壳自身的导入表信息
 - 输出参数
    lpOffset: 导入表偏移(相对于外壳第一段基地址), 可为NULL
    lpSize: 导入表大小, 可为NULL
 - 返回值
    导入表地址
*/
static BYTE *GetShellImpTab(_Out_opt_ DWORD *lpOffset, _Out_opt_ DWORD *lpSize);

/*
 - 描述
    根据外壳存储位置, 调整其导入表数据
 - 输入参数
    lpShell: 外壳基地址
    lpShellSecHeader: 外壳所在的节区表项
*/
static void AdjustShellImpTab(_In_ BYTE *lpShell, _In_ IMAGE_SECTION_HEADER *lpShellSecHeader);

/*
 - 描述
    获取外壳第一段(初始化段)信息
 - 输出参数
    lpOffset: 段偏移(相对于外壳基地址, 实际值恒为零), 可为NULL
    lpSize: 段大小, 可为NULL
 - 返回值
    段地址
*/
static BYTE *GetInitCode(_Out_opt_ DWORD *lpOffset, _Out_opt_ DWORD *lpSize);

/*
 - 描述
    获取外壳第二段(核心段)信息
 - 输出参数
    lpOffset: 段偏移(相对于外壳基地址), 可为NULL
    lpSize: 段大小, 可为NULL
 - 返回值
    段地址
*/
static BYTE *GetShellCode(_Out_opt_ DWORD *lpOffset, _Out_opt_ DWORD *lpSize);

/*
 - 描述
    获取外壳加密段的信息
 - 输入参数
    lpShell: 外壳基地址
 - 返回值
    加密信息
*/
static INIT_DATA *GetInitData(_In_ BYTE *lpShell);

/*
 - 描述
    获取原始PE文件的相关信息
 - 输入参数
    lpShell: 外壳基地址
 - 返回值
    原始PE文件信息
*/
static ORIGIN_DATA *GetOriginData(_In_ BYTE *lpShell);

/*
    安装外壳
*/
bool SetupShell(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _In_ const BYTE *lpNewImpTab, _In_ DWORD dwNewImpTabSize, 
    _In_ const BYTE *lpSecEncryInfo, _In_ DWORD dwSecEncryInfoSize)
{
    assert(lpImageInfo != NULL);
    assert(lpNewImpTab != NULL);
    assert(lpSecEncryInfo != NULL);

    IMAGE_NT_HEADERS *lpNtHeader = lpImageInfo->lpNtHeader;

    // 拼接外壳
    DWORD dwShellSize = CalcShellSize(dwNewImpTabSize);
    BYTE *lpShell = (BYTE*)VirtualAlloc(NULL, dwShellSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // 拷贝外壳第一段(初始化段)
    DWORD dwInitCodeSize = 0, dwInitCodeOffset = 0;
    BYTE *lpSrcInitCode = GetInitCode(&dwInitCodeOffset, &dwInitCodeSize);
    BYTE *lpInitCode = lpShell + dwInitCodeOffset;
    CopyMemory(lpInitCode, lpSrcInitCode, dwInitCodeSize);

    // 拷贝外壳第二段(核心段)
    DWORD dwShellCodeSize = 0, dwShellCodeOffset = 0;
    BYTE *lpSrcShellCode = GetShellCode(&dwShellCodeOffset, &dwShellCodeSize);
    BYTE *lpShellCode = lpShell + dwShellCodeOffset;
    CopyMemory(lpShellCode, lpSrcShellCode, dwShellCodeSize);

    // 拷贝外壳第三段(变形后的原导入表数据)
    CopyMemory(lpShellCode + dwShellCodeSize, lpNewImpTab, dwNewImpTabSize);

    // 为外壳中的变量赋值
    ORIGIN_DATA *lpOriginData = GetOriginData(lpShell);
    lpOriginData->dwEntryPoint = lpNtHeader->OptionalHeader.AddressOfEntryPoint;
    lpOriginData->dwImpTabOffset = dwShellCodeSize;
    lpOriginData->dwRelocTabRva = lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    lpOriginData->dwTlsTabRva = lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    lpOriginData->dwImageBase = lpNtHeader->OptionalHeader.ImageBase;

    // 拷贝节区加密信息
    assert(dwSecEncryInfoSize <= sizeof(lpOriginData->szSecEncryInfo));
    CopyMemory(lpOriginData->szSecEncryInfo, lpSecEncryInfo, dwSecEncryInfoSize);

    // 加密外壳第二, 三段
    EncryData(lpShellCode, dwShellCodeSize + dwNewImpTabSize);

    // 保存外壳加密段信息
    INIT_DATA *lpInitData = GetInitData(lpShell);
    lpInitData->dwShellPackOffset = dwInitCodeSize;
    lpInitData->dwShellPackSize = dwShellCodeSize + dwNewImpTabSize;

    // 调整外壳自身的导入表
    WORD wSecNum = lpNtHeader->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *lpShellSecHeader = &lpImageInfo->lpSecHeader[wSecNum - 1];
    AdjustShellImpTab(lpShell, lpShellSecHeader);

    // 将外壳安装至PE映像的指定节区
    assert(dwShellSize <= lpShellSecHeader->Misc.VirtualSize);
    CopyMemory(lpImageInfo->lpImageBase + lpShellSecHeader->VirtualAddress, lpShell, dwShellSize);

    DWORD dwFileAlign = lpNtHeader->OptionalHeader.FileAlignment;
    DWORD dwSecAlign = lpNtHeader->OptionalHeader.SectionAlignment;

    // 设置节区表项信息
    lpShellSecHeader->SizeOfRawData = AlignSize(dwShellSize, dwFileAlign);
    lpShellSecHeader->Misc.VirtualSize = AlignSize(dwShellSize, dwSecAlign);

    // 修改代码入口点至外壳段
    lpNtHeader->OptionalHeader.AddressOfEntryPoint = lpShellSecHeader->VirtualAddress;
    lpNtHeader->OptionalHeader.CheckSum = 0;

    // 修改导入表数据目录, 使其指向外壳导入表
    DWORD dwShellImpTabOffset = 0, dwShellImpTabSize = 0;
    GetShellImpTab(&dwShellImpTabOffset, &dwShellImpTabSize);
    lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        lpShellSecHeader->VirtualAddress + dwShellImpTabOffset;
    lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwShellImpTabSize;

    // 清除部分数据目录项
    ZeroMemory(&lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG],
        sizeof(IMAGE_DATA_DIRECTORY));
    ZeroMemory(&lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG],
        sizeof(IMAGE_DATA_DIRECTORY));
    ZeroMemory(&lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE],
        sizeof(IMAGE_DATA_DIRECTORY));
    ZeroMemory(&lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS],
        sizeof(IMAGE_DATA_DIRECTORY));  // TLS表
    ZeroMemory(&lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
        sizeof(IMAGE_DATA_DIRECTORY));  // 重定位表
    return true;
}

/*
    计算外壳总大小
*/
DWORD CalcShellSize(_In_ DWORD dwNewImpTabSize)
{
    DWORD dwInitCodeSize = 0, dwShellCodeSize = 0;
    GetInitCode(NULL, &dwInitCodeSize);     // 外壳第一段
    GetShellCode(NULL, &dwShellCodeSize);   // 外壳第二段
    return dwInitCodeSize + dwShellCodeSize + dwNewImpTabSize /* 外壳第三段 */;
}

/*
    数据加密
*/  
void EncryData(_In_ BYTE *lpData, _In_ DWORD dwSize)
{
    assert(lpData != NULL);

    for (DWORD i = 0; i != dwSize; ++i)
    {
        lpData[i] ^= 0xFF;
    }
}

/*
    获取外壳自身的导入表信息
*/
BYTE *GetShellImpTab(_Out_opt_ DWORD *lpOffset, _Out_opt_ DWORD *lpSize)
{
    if (lpSize != NULL)
    {
        *lpSize = (BYTE*)&ImpTabEnd - (BYTE*)&ImpTabBegin;
    }

    if (lpOffset != NULL)
    {
        *lpOffset = (BYTE*)&ImpTabBegin - (BYTE*)&InitBegin;
    }

    return (BYTE*)&ImpTabBegin;
}

/*
    根据外壳存储位置, 调整其导入表数据
*/
void AdjustShellImpTab(_In_ BYTE *lpShell, _In_ IMAGE_SECTION_HEADER *lpShellSecHeader)
{
    assert(lpShell != NULL);
    assert(lpShellSecHeader != NULL);

    DWORD dwImpTabOffset = 0;
    GetShellImpTab(&dwImpTabOffset, NULL);

    // 在导入表数据上增加RVA偏移
    DWORD dwImpTabRva = lpShellSecHeader->VirtualAddress + dwImpTabOffset;
    for (IMAGE_IMPORT_DESCRIPTOR *lpDescriptor = 
        (IMAGE_IMPORT_DESCRIPTOR*)(lpShell + dwImpTabOffset); 
        lpDescriptor->Name != NULL; ++lpDescriptor)
    {
        if (lpDescriptor->OriginalFirstThunk != NULL)
        {
            lpDescriptor->OriginalFirstThunk += dwImpTabRva;
        }

        lpDescriptor->Name += dwImpTabRva;

        IMAGE_THUNK_DATA *lpThunk = (IMAGE_THUNK_DATA*)
            (lpShell + dwImpTabOffset + lpDescriptor->FirstThunk);
        lpDescriptor->FirstThunk += dwImpTabRva;
        while (lpThunk->u1.AddressOfData != NULL)
        {
            lpThunk->u1.AddressOfData += dwImpTabRva;
            ++lpThunk;
        }
    }
}

/*
    获取外壳加密段的信息
*/
INIT_DATA *GetInitData(_In_ BYTE *lpShell)
{
    assert(lpShell != NULL);

    // 根据外壳基地址进行数据重定位
    DWORD dwInitCodeOffset = 0;
    BYTE *lpSrcInitCode = GetInitCode(&dwInitCodeOffset, NULL);
    BYTE *lpInitCode = lpShell + dwInitCodeOffset;
    return (INIT_DATA*)((BYTE*)&InitData - lpSrcInitCode + lpInitCode);
}

/*
    获取原始PE文件的相关信息
*/
ORIGIN_DATA *GetOriginData(_In_ BYTE *lpShell)
{
    assert(lpShell != NULL);

    // 根据外壳基地址进行数据重定位
    DWORD dwShellCodeOffset = 0;
    BYTE *lpSrcShellCode = GetShellCode(&dwShellCodeOffset, NULL);
    BYTE *lpShellCode = lpShell + dwShellCodeOffset;
    return (ORIGIN_DATA*)((BYTE*)&OriginData - lpSrcShellCode + lpShellCode);
}

/*
    获取外壳第一段(初始化段)信息
*/
BYTE *GetInitCode(_Out_opt_ DWORD *lpOffset, _Out_opt_ DWORD *lpSize)
{
    if (lpSize != NULL)
    {
        *lpSize = (BYTE*)&InitEnd - (BYTE*)&InitBegin;
    }

    if (lpOffset != NULL)
    {
        *lpOffset = (BYTE*)&InitBegin - (BYTE*)&Begin;
    }

    return (BYTE*)&InitBegin;
}

/*
    获取外壳第二段(核心段)信息
*/
BYTE *GetShellCode(_Out_opt_ DWORD *lpOffset, _Out_opt_ DWORD *lpSize)
{
    if (lpSize != NULL)
    {
        *lpSize = (BYTE*)&ShellEnd - (BYTE*)&ShellBegin;
    }

    if (lpOffset != NULL)
    {
        *lpOffset = (BYTE*)&ShellBegin - (BYTE*)&Begin;
    }

    return (BYTE*)&ShellBegin;
}