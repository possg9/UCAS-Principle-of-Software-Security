#include "Import.h"
#include <assert.h>

#pragma warning(disable:4047 4267)

/*
    回调函数, 枚举导入表时调用
*/
typedef DWORD(*LPFN_ENUM_IMP_TAB_CALLBACK)(
    _In_ PE_IMAGE_INFO *lpImageInfo, 
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, 
    _Inout_opt_ void *lpArg);

/*
 - 描述
    枚举导入表
 - 输入参数
    lpImageInfo: PE映像信息
    lpCallBack: 回调函数
    lpArg: 回调参数
*/
static void EnumImpTab(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ LPFN_ENUM_IMP_TAB_CALLBACK lpCallBack, _Inout_opt_ void *lpArg);

/*
    回调函数, 用于计算变形后的导入表大小
*/
static DWORD CalcNewImpTabSizeCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, _Inout_ void *lpArg);
    
/*
    回调函数, 用于导入表变形
*/
static DWORD TransformImpTabCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, _Inout_ void *lpArg);
    
/*
    回调函数, 用于清空原始导入表
*/
static DWORD ClearImpTabCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, _Inout_opt_ void *lpArg);


/*
    计算变形后的导入表大小
*/
DWORD CalcNewImpTabSize(_In_ PE_IMAGE_INFO *lpImageInfo)
{
    assert(lpImageInfo != NULL);

    DWORD dwSize = 0;
    EnumImpTab(lpImageInfo, &CalcNewImpTabSizeCallBack, &dwSize);
    return dwSize;
}

/*
    导入表变形
*/
DWORD TransformImpTab(_In_ PE_IMAGE_INFO *lpImageInfo,
    _Out_writes_bytes_to_opt_(dwBufSize, return) BYTE *lpBuffer, _In_ DWORD dwBufSize)
{
    assert(lpImageInfo != NULL);
    
    // 计算变形后的导入表大小
    DWORD dwNewImpTabSize = CalcNewImpTabSize(lpImageInfo);
    if (lpBuffer != NULL && dwBufSize >= dwNewImpTabSize)
    {
        EnumImpTab(lpImageInfo, &TransformImpTabCallBack, &lpBuffer);
    }

    return dwNewImpTabSize;
}

/*
    清空原始导入表
*/
void ClearImpTab(_In_ PE_IMAGE_INFO *lpImageInfo)
{
    assert(lpImageInfo != NULL);
    
    // 清空导入表
    EnumImpTab(lpImageInfo, &ClearImpTabCallBack, NULL);

    IMAGE_NT_HEADERS *lpNtHeader = lpImageInfo->lpNtHeader;

    // 清空绑定导入表
    IMAGE_DATA_DIRECTORY *lpBoundImpDir = &lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if (lpBoundImpDir->VirtualAddress != NULL && lpBoundImpDir->Size > 0)
    {
        PIMAGE_BOUND_IMPORT_DESCRIPTOR *lpBoundImp = (PIMAGE_BOUND_IMPORT_DESCRIPTOR*)
            RvaToVa(lpImageInfo->lpImageBase, lpBoundImpDir->VirtualAddress);
        ZeroMemory(lpBoundImp, lpBoundImpDir->Size);
        ZeroMemory(lpBoundImpDir, sizeof(IMAGE_DATA_DIRECTORY));
    }
    
    // 清空导入地址表(IAT)
    IMAGE_DATA_DIRECTORY *lpIatDir = &lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (lpIatDir->VirtualAddress != NULL && lpIatDir->Size > 0)
    {
        PIMAGE_BOUND_IMPORT_DESCRIPTOR *lpIat = (PIMAGE_BOUND_IMPORT_DESCRIPTOR*)
            RvaToVa(lpImageInfo->lpImageBase, lpIatDir->VirtualAddress);
        ZeroMemory(lpIat, lpIatDir->Size);
        ZeroMemory(lpIatDir, sizeof(IMAGE_DATA_DIRECTORY));
    }
    
    // 清空延迟导入表
    ZeroMemory(&lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT],
        sizeof(IMAGE_DATA_DIRECTORY));
}

/*
    枚举导入表
*/
void EnumImpTab(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _In_ LPFN_ENUM_IMP_TAB_CALLBACK lpCallBack, _Inout_opt_ void *lpArg)
{
    assert(lpImageInfo != NULL);
    assert(lpCallBack != NULL);

    IMAGE_DATA_DIRECTORY *lpImpDir = &lpImageInfo->lpNtHeader->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (lpImpDir->VirtualAddress != NULL && lpImpDir->Size > 0)
    {
        IMAGE_IMPORT_DESCRIPTOR *lpImp = (IMAGE_IMPORT_DESCRIPTOR*)
            RvaToVa(lpImageInfo->lpImageBase, lpImpDir->VirtualAddress);
        for (IMAGE_IMPORT_DESCRIPTOR *lpCurImp = lpImp;
            lpCurImp->Name != NULL; ++lpCurImp)
        {
            // 遍历IMAGE_IMPORT_DESCRIPTOR项目, 调用回调函数
            lpCallBack(lpImageInfo, lpCurImp, lpArg);
        }
    }
}

/*
    回调函数, 用于计算变形后的导入表大小
*/
DWORD CalcNewImpTabSizeCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, _Inout_ void *lpArg)
{
    assert(lpImageInfo != NULL);
    assert(lpDescriptor != NULL);
    assert(lpArg != NULL);
    
    // 累计大小由lpArg参数传入传出
    DWORD dwSize = *(DWORD*)lpArg;
    
    dwSize += sizeof(IMAGE_THUNK_DATA);     // FirstThunk
    dwSize += sizeof(BYTE);     // Dll名称长度

    // Dll名称
    BYTE *lpImageBase = lpImageInfo->lpImageBase;
    char *lpDllName = (char*)RvaToVa(lpImageBase, lpDescriptor->Name);
    dwSize += (strlen(lpDllName) + 1) * sizeof(char);

    dwSize += sizeof(DWORD);    // 函数数量

    IMAGE_THUNK_DATA *lpThunk = NULL;
    if (lpDescriptor->OriginalFirstThunk != NULL)
    {
        lpThunk = (IMAGE_THUNK_DATA*)RvaToVa(lpImageBase, lpDescriptor->OriginalFirstThunk);
    }
    else
    {
        lpThunk = (IMAGE_THUNK_DATA*)RvaToVa(lpImageBase, lpDescriptor->FirstThunk);
    }
    
    // 遍历导入函数
    while (lpThunk->u1.AddressOfData != NULL)
    {
        dwSize += sizeof(BYTE);     // 函数名称长度或0x00
         
         // 函数由序号导入
        if (IMAGE_SNAP_BY_ORDINAL(lpThunk->u1.Ordinal))
        {
            dwSize += sizeof(DWORD);    // 函数序号
        }
        // 函数由名称导入
        else
        {
            // 函数名称
            IMAGE_IMPORT_BY_NAME *lpFuncName = (IMAGE_IMPORT_BY_NAME*)
                RvaToVa(lpImageBase, lpThunk->u1.AddressOfData);
            dwSize += (strlen(lpFuncName->Name) + 1) * sizeof(char);
        }

        ++lpThunk;
    }

    *(DWORD*)lpArg = dwSize;
    return 0;
}

/*
    回调函数, 用于导入表变形
*/
DWORD TransformImpTabCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, _Inout_ void *lpArg)
{
    assert(lpImageInfo != NULL);
    assert(lpDescriptor != NULL);
    assert(lpArg != NULL);
    
    // 存储位置由lpArg参数传入传出
    BYTE *lpBuffer = *(BYTE**)lpArg;

    // 保存FirstThunk
    *(DWORD*)lpBuffer = lpDescriptor->FirstThunk;
    lpBuffer += sizeof(IMAGE_THUNK_DATA);
        
    // 保存Dll名称长度
    BYTE *lpImageBase = lpImageInfo->lpImageBase;
    char *lpDllName = (char*)RvaToVa(lpImageBase, lpDescriptor->Name);
    BYTE byDllNameSize = (strlen(lpDllName) + 1) * sizeof(char);
    *lpBuffer = byDllNameSize;
    lpBuffer += sizeof(BYTE);

    // 保存Dll名称
    CopyMemory(lpBuffer, lpDllName, byDllNameSize);
    lpBuffer += byDllNameSize;
    
    // 保存函数数量
    DWORD *lpFuncNum = (DWORD*)lpBuffer;
    *lpFuncNum = 0;
    lpBuffer += sizeof(DWORD);

    IMAGE_THUNK_DATA *lpThunk = NULL;
    if (lpDescriptor->OriginalFirstThunk != NULL)
    {
        lpThunk = (IMAGE_THUNK_DATA*)RvaToVa(lpImageBase, lpDescriptor->OriginalFirstThunk);
    }
    else
    {
        lpThunk = (IMAGE_THUNK_DATA*)RvaToVa(lpImageBase, lpDescriptor->FirstThunk);
    }
    
    // 遍历导入函数
    while (lpThunk->u1.AddressOfData != NULL)
    { 
        // 函数由序号导入
        if (IMAGE_SNAP_BY_ORDINAL(lpThunk->u1.Ordinal))
        {
            // 名称长度字段设置为0
            *lpBuffer = 0;
            lpBuffer += sizeof(BYTE);
    
            // 保存函数序号
            *(DWORD*)lpBuffer = IMAGE_ORDINAL(lpThunk->u1.Ordinal);
            lpBuffer += sizeof(DWORD);
        }
        // 函数由名称导入
        else
        {
            // 保存函数名称长度
            IMAGE_IMPORT_BY_NAME *lpFuncName = (IMAGE_IMPORT_BY_NAME*)
                RvaToVa(lpImageBase, lpThunk->u1.AddressOfData); 
            BYTE byFuncNameSize = (strlen(lpFuncName->Name) + 1) * sizeof(char);
            *lpBuffer = byFuncNameSize;
            lpBuffer += sizeof(BYTE);
            
            // 保存函数名称
            CopyMemory(lpBuffer, lpFuncName->Name, byFuncNameSize);
            lpBuffer += byFuncNameSize;
        }

        ++lpThunk;
        ++*lpFuncNum;   // 递增函数数量
    }

    *(BYTE**)lpArg = lpBuffer;
    return 0;
}

/*
    回调函数, 用于清空原始导入表
*/
DWORD ClearImpTabCallBack(_In_ PE_IMAGE_INFO *lpImageInfo,
    _In_ IMAGE_IMPORT_DESCRIPTOR *lpDescriptor, _Inout_opt_ void *lpArg)
{
    assert(lpImageInfo != NULL);
    assert(lpDescriptor != NULL);
    
    // 清空Dll名称
    BYTE *lpImageBase = lpImageInfo->lpImageBase;
    char *lpDllName = (char*)RvaToVa(lpImageBase, lpDescriptor->Name);
    ZeroMemory(lpDllName, strlen(lpDllName) * sizeof(char));

    IMAGE_THUNK_DATA *lpThunk = NULL;
    if (lpDescriptor->OriginalFirstThunk != NULL)
    {
        // 清空导入名称表(INT)
        lpThunk = (IMAGE_THUNK_DATA*)RvaToVa(lpImageBase, lpDescriptor->OriginalFirstThunk);
        while (lpThunk->u1.AddressOfData != NULL)
        {
            if (!IMAGE_SNAP_BY_ORDINAL(lpThunk->u1.Ordinal))
            {
                // 清空函数名称
                IMAGE_IMPORT_BY_NAME *lpFuncName = (IMAGE_IMPORT_BY_NAME*)
                    RvaToVa(lpImageBase, lpThunk->u1.AddressOfData);
                ZeroMemory(lpFuncName,
                    strlen((char*)lpFuncName->Name) * sizeof(char) + sizeof(WORD));
            }
            
            ZeroMemory(lpThunk, sizeof(IMAGE_THUNK_DATA));
            ++lpThunk;
        }
    }
    
    // 清空导入地址表(IAT)
    lpThunk = (IMAGE_THUNK_DATA*)RvaToVa(lpImageBase, lpDescriptor->FirstThunk);
    while (lpThunk->u1.AddressOfData != NULL)
    {
        ZeroMemory(lpThunk, sizeof(IMAGE_THUNK_DATA));
        ++lpThunk;
    }

    ZeroMemory(lpDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    return 0;
}