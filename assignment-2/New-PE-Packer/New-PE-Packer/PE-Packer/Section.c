#include "Section.h"
#include <assert.h>
#include "Shell.h"


/*
    回调函数, 枚举节区表时调用
*/
typedef DWORD(*LPFN_ENUM_SECTION_CALLBACK)(
    _In_ PE_IMAGE_INFO *lpImageInfo,            // PE映像信息
    _In_ IMAGE_SECTION_HEADER *lpSecHeader,     // 节区表项
    _Inout_opt_ void *lpArg);                   // 可选参数
    
/*
 - 描述
    判断节区是否可被加密
 - 输入参数
    lpSecHeader: 节区表项
 - 返回值
    返回true表示节区可被加密; 否则返回false
*/
static bool IsSectionCanEncrypted(_In_ const IMAGE_SECTION_HEADER *lpSecHeader);

/*
 - 描述
    保存节区加密信息, 用于外壳解密
 - 输入参数
    lpBuffer: 存储缓冲区
    dwRva: 节区RVA
    dwSize: 加密大小
 - 返回值
    新的缓冲区存储地址
*/
static BYTE *SaveEncryInfo(_In_ BYTE *lpBuffer, _In_ DWORD dwRva, _In_ DWORD dwSize);

/*
 - 描述
    排除尾部零数据, 计算节区实际大小
 - 输入参数
    lpImageInfo: PE映像信息
    lpSecHeader: 节区表项
 - 返回值
    节区实际大小
*/
static DWORD CalcSectionMinSize(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ const IMAGE_SECTION_HEADER *lpSecHeader);
    
/*
 - 描述
    枚举节区表
 - 输入参数
    lpImageInfo: PE映像信息
    lpCallBack: 回调函数
    lpArg: 回调参数
*/
static void EnumSection(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ LPFN_ENUM_SECTION_CALLBACK lpCallBack, _Inout_opt_ void *lpArg);
    
/*
    回调函数, 用于清空节区名称
*/
static DWORD ClearSectionNameCallBack(_In_opt_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_SECTION_HEADER *lpSecHeader, _Inout_opt_ void *lpArg);
    
/*
    回调函数, 用于计算节区加密信息的大小
*/
static DWORD CalcEncryInfoSizeCallBack(_In_opt_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_SECTION_HEADER *lpSecHeader, _Inout_ void *lpArg);
    
/*
    回调函数, 用于加密节区数据
*/
static DWORD EncrySectionCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_SECTION_HEADER *lpSecHeader, _Inout_ void *lpArg);


/*
    在PE映像尾部增加节区
*/
WORD AppendSection(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _In_reads_or_z_opt_(IMAGE_SIZEOF_SHORT_NAME) const char *lpName,
    _In_ DWORD dwSize, _Out_ IMAGE_SECTION_HEADER *lpNewSecHeader)
{
    assert(lpImageInfo != NULL);
    assert(lpName != NULL);
    assert(lpNewSecHeader != NULL);

    // 设置节区属性
    ZeroMemory(lpNewSecHeader, sizeof(IMAGE_SECTION_HEADER));
    lpNewSecHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    if (lpName != NULL)
    {
        // 设置节区名称
        size_t nNameLen = min(strlen(lpName), IMAGE_SIZEOF_SHORT_NAME);
        CopyMemory(lpNewSecHeader->Name, lpName, nNameLen);
    }

    WORD wSecNum = lpImageInfo->lpNtHeader->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *lpSecHeader = lpImageInfo->lpSecHeader;

    DWORD dwFileAlign = lpImageInfo->lpNtHeader->OptionalHeader.FileAlignment;
    DWORD dwSecAlign = lpImageInfo->lpNtHeader->OptionalHeader.SectionAlignment;

    // 计算对齐后的节区大小
    DWORD dwNewSecRawSize = AlignSize(dwSize, dwFileAlign);
    DWORD dwNewSecVirSize = AlignSize(dwSize, dwSecAlign);
    lpNewSecHeader->SizeOfRawData = dwNewSecRawSize;
    lpNewSecHeader->Misc.VirtualSize = dwSize;

    // 获取当前文件头大小
    DWORD dwCurHeaderSize = CalcHeadersSize(lpImageInfo->lpImageBase, NULL, NULL);
    DWORD dwCurHeaderRawSize = AlignSize(dwCurHeaderSize, dwFileAlign);
    DWORD dwCurHeaderVirSize = AlignSize(dwCurHeaderRawSize, dwSecAlign);

    // 计算新的文件头大小
    DWORD dwNewHeaderSize = dwCurHeaderSize + sizeof(IMAGE_SECTION_HEADER);
    DWORD dwNewHeaderRawSize = AlignSize(dwNewHeaderSize, dwFileAlign);
    DWORD dwNewHeaderVirSize = AlignSize(dwNewHeaderSize, dwSecAlign);

    // 计算文件头增长大小
    DWORD dwHeaderRawIncSize = 0;
    if (dwNewHeaderRawSize > dwCurHeaderRawSize)
    {
        dwHeaderRawIncSize = dwNewHeaderRawSize - dwCurHeaderRawSize;
    }

    DWORD dwHeaderVirIncSize = 0;
    if (dwNewHeaderVirSize > dwCurHeaderVirSize)
    {
        dwHeaderVirIncSize = dwNewHeaderVirSize - dwCurHeaderVirSize;
    }

    // 新节区起始地址, 根据文件头增长情况调整
    lpNewSecHeader->VirtualAddress = lpImageInfo->dwImageSize + dwHeaderVirIncSize;
    lpNewSecHeader->PointerToRawData = lpSecHeader[wSecNum - 1].PointerToRawData +
        AlignSize(lpSecHeader[wSecNum - 1].SizeOfRawData, dwFileAlign) + dwHeaderRawIncSize;

    // 调整PE_IMAGE_INFO结构
    DWORD dwNewImageSize = lpImageInfo->dwImageSize + dwNewSecVirSize + dwHeaderVirIncSize;
    BYTE *lpNewImageBase = (BYTE*)VirtualAlloc(NULL,
        dwNewImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CopyMemory(lpNewImageBase, lpImageInfo->lpImageBase, dwCurHeaderRawSize);

    DWORD dwFirstSecRva = dwCurHeaderVirSize;
    CopyMemory(lpNewImageBase + dwHeaderVirIncSize + dwFirstSecRva,
        lpImageInfo->lpImageBase + dwFirstSecRva, lpImageInfo->dwImageSize - dwFirstSecRva);

    lpImageInfo->lpNtHeader = (IMAGE_NT_HEADERS*)
        (lpNewImageBase + ((BYTE*)lpImageInfo->lpNtHeader - lpImageInfo->lpImageBase));
    lpImageInfo->lpSecHeader = (IMAGE_SECTION_HEADER*)
        (lpNewImageBase + ((BYTE*)lpImageInfo->lpSecHeader - lpImageInfo->lpImageBase));
    VirtualFree(lpImageInfo->lpImageBase, 0, MEM_RELEASE);
    lpImageInfo->lpImageBase = lpNewImageBase;

    if (dwHeaderVirIncSize != 0 || dwHeaderRawIncSize != 0)
    {
        // 根据文件头增长情况, 调整节区起始地址
        for (WORD i = 0; i != wSecNum; ++i)
        {
            lpImageInfo->lpSecHeader[i].VirtualAddress += dwHeaderVirIncSize;
            lpImageInfo->lpSecHeader[i].PointerToRawData += dwHeaderRawIncSize;
        }
    }

    lpImageInfo->dwImageSize = dwNewImageSize;
    lpImageInfo->lpNtHeader->OptionalHeader.CheckSum = 0;
    lpImageInfo->lpNtHeader->OptionalHeader.SizeOfImage = dwNewImageSize;
    lpImageInfo->lpNtHeader->OptionalHeader.SizeOfInitializedData += dwNewSecRawSize;
    lpImageInfo->lpNtHeader->OptionalHeader.SizeOfHeaders = dwNewHeaderRawSize;

    CopyMemory((BYTE*)&lpImageInfo->lpSecHeader[wSecNum],
        lpNewSecHeader, sizeof(IMAGE_SECTION_HEADER));
    return ++lpImageInfo->lpNtHeader->FileHeader.NumberOfSections;  // 递增节区数量
}

/*
    计算节区加密信息的大小
*/
DWORD CalcEncryInfoSize(_In_ const PE_IMAGE_INFO *lpImageInfo)
{
    DWORD dwSize = 0;
    EnumSection((PE_IMAGE_INFO*)lpImageInfo,
        &CalcEncryInfoSizeCallBack, &dwSize);
    return dwSize;
}

/*
    加密节区数据
*/
DWORD EncrySection(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _Out_writes_bytes_to_opt_(dwBufSize, return) BYTE *lpInfoBuffer, 
    _In_ DWORD dwBufSize)
{
    DWORD dwEncryInfoSize = CalcEncryInfoSize(lpImageInfo);
    if (lpInfoBuffer != NULL && dwBufSize >= dwEncryInfoSize)
    {
        ZeroMemory(lpInfoBuffer, dwBufSize);
        EnumSection(lpImageInfo, &EncrySectionCallBack, &lpInfoBuffer);
    }

    return dwEncryInfoSize;
}

/*
    清空节区名称
*/
void ClearSectionName(_In_ PE_IMAGE_INFO *lpImageInfo)
{
    EnumSection(lpImageInfo, &ClearSectionNameCallBack, NULL);
}

/*
    判断节区是否可被加密
*/
bool IsSectionCanEncrypted(_In_ const IMAGE_SECTION_HEADER *lpSecHeader)
{
    assert(lpSecHeader != NULL);

    // 可加密的节区名称合集
    static const char *const lpSecNameList[] =
    {
        ".text", ".data", ".rdata", "CODE", "DATA",
    };

    for (size_t i = 0; i != _countof(lpSecNameList); ++i)
    {
        if (strncmp((char*)lpSecHeader->Name,
            lpSecNameList[i], IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            return true;
        }
    }

    return false;
}

/*
    保存节区加密信息, 用于外壳解密
*/
BYTE *SaveEncryInfo(_In_ BYTE *lpBuffer, _In_ DWORD dwRva, _In_ DWORD dwSize)
{
    assert(lpBuffer != NULL);

    *(DWORD*)lpBuffer = dwRva;      // 节区RVA
    lpBuffer += sizeof(DWORD);
    
    *(DWORD*)lpBuffer = dwSize;     // 加密大小
    lpBuffer += sizeof(DWORD);

    return lpBuffer;
}

/*
    排除尾部零数据, 计算节区实际大小
*/
DWORD CalcSectionMinSize(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ const IMAGE_SECTION_HEADER *lpSecHeader)
{
    assert(lpImageInfo != NULL);
    assert(lpSecHeader != NULL);

    DWORD dwSize = lpSecHeader->SizeOfRawData;
    const BYTE *lpData = lpImageInfo->lpImageBase
        + lpSecHeader->VirtualAddress + (dwSize - 1);
    while (dwSize != 0 && *lpData == 0)
    {
        --lpData;
        --dwSize;
    }

    return dwSize;
}

/*
    枚举节区表
*/
void EnumSection(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ LPFN_ENUM_SECTION_CALLBACK lpCallBack, _Inout_opt_ void *lpArg)
{
    assert(lpImageInfo != NULL);
    assert(lpCallBack != NULL);

    WORD wSecNum = lpImageInfo->lpNtHeader->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *lpSecHeader = lpImageInfo->lpSecHeader;
    for (WORD i = 0; i != wSecNum; ++i, ++lpSecHeader)
    {
        // 遍历IMAGE_SECTION_HEADER项目, 调用回调函数
        lpCallBack(lpImageInfo, lpSecHeader, lpArg);
    }
}

/*
    回调函数, 用于清空节区名称
*/
DWORD ClearSectionNameCallBack(_In_opt_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_SECTION_HEADER *lpSecHeader, _Inout_opt_ void *lpArg)
{
    assert(lpSecHeader != NULL);

    ZeroMemory(lpSecHeader->Name, sizeof(lpSecHeader->Name));
    return 0;
}

/*
    回调函数, 用于加密节区数据
*/
DWORD EncrySectionCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_SECTION_HEADER *lpSecHeader, _Inout_ void *lpArg)
{
    assert(lpImageInfo != NULL);
    assert(lpSecHeader != NULL);

    if (IsSectionCanEncrypted(lpSecHeader))
    {
        BYTE *lpInfoBuffer = *(BYTE**)lpArg;

        // 计算加密大小
        DWORD dwMinSize = CalcSectionMinSize(lpImageInfo, lpSecHeader);
        if (dwMinSize != 0)
        {
            // 加密节区
            BYTE *lpBase = lpImageInfo->lpImageBase + lpSecHeader->VirtualAddress;
            EncryData(lpBase, dwMinSize);

            // 保存加密信息
            lpInfoBuffer = SaveEncryInfo(lpInfoBuffer, lpSecHeader->VirtualAddress, dwMinSize);
            lpSecHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
        }

        *(BYTE**)lpArg = lpInfoBuffer;
        return dwMinSize;
    }
    else
    {
        return 0;
    }
}

/*
    回调函数, 用于计算节区加密信息的大小
*/
DWORD CalcEncryInfoSizeCallBack(_In_opt_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_SECTION_HEADER *lpSecHeader, _Inout_ void *lpArg)
{
    assert(lpArg != NULL);

    if (IsSectionCanEncrypted(lpSecHeader))
    {
        // 节区RVA及加密大小
        *(DWORD*)lpArg += sizeof(DWORD) * 2;
    }

    return 0;
}