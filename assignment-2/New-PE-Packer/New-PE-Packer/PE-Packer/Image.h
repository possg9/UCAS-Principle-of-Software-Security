/************************************
 - 文件名称
    Image.h, Image.c
 - 描述
    定义PE映像结构
    判断PE格式
    PE映像的加载, 释放和导出
*************************************/
#pragma once
#include <stdbool.h>
#include <Windows.h>

/*
    PE映像结构
*/
typedef struct _PE_IMAGE_INFO
{
    DWORD dwImageSize;                  // 映像大小
    BYTE *lpImageBase;                  // 映像基地址
    IMAGE_NT_HEADERS *lpNtHeader;       // NT文件头地址
    IMAGE_SECTION_HEADER *lpSecHeader;  // 节区表地址
    DWORD dwExtDataSize;                // 附加数据大小
    BYTE *lpExtData;                    // 附加数据
} PE_IMAGE_INFO;

/*
 - 描述
    判断PE格式
 - 输入参数
    lpFileBase: 文件数据
 - 返回值
    如果为PE格式, 返回true; 否则返回false
*/
bool IsPeFile(_In_ const BYTE *lpFileBase);

/*
 - 描述
    将PE文件映射至内存
 - 输入参数
    lpFileBase: 文件数据
    dwFileSize: 文件大小
 - 输出参数
    lpImageInfo: PE映像信息
*/
void LoadPeImage(_In_reads_bytes_(dwFileSize) const BYTE *lpFileBase,
    _In_ DWORD dwFileSize, _Out_ PE_IMAGE_INFO *lpImageInfo);

/*
 - 描述
    计算PE文件头大小
 - 输入参数
    lpFileBase: 文件数据
 - 输出参数
    lpDosHeaderSize：DOS文件头大小
    lpNtHeaderSize：NT文件头大小
 - 返回值
    PE文件头大小
*/
DWORD CalcHeadersSize(_In_ const BYTE *lpFileBase,
    _Out_opt_ DWORD *lpDosHeaderSize, _Out_opt_ DWORD *lpNtHeaderSize);

/*
 - 描述
    Free image
 - 输入参数
    lpImageInfo: PE映像信息
 - 返回值
    如果映像为空, 返回false; 否则返回true
*/
bool FreePeImage(_Inout_ PE_IMAGE_INFO *lpImageInfo);

/*
 - 描述
    将PE映像保存至文件
 - 输入参数
    lpFileName: 文件名称
    lpImageInfo: PE映像信息
 - 输出参数
    lpFileSize: 文件大小, 可为NULL
 - 返回值
    保存成功, 返回true; 否则为false
*/
bool WriteImageToFile(_In_z_ const wchar_t *lpFileName,
    _In_ const PE_IMAGE_INFO *lpImageInfo, _Out_opt_ DWORD *lpFileSize);
    
/*
 - 描述
    将相对虚拟地址(RVA)转换为虚拟地址(VA)
 - 输入参数
    lpImageBase: 映像基地址
    dwRva: 相对虚拟地址
 - 返回值
    虚拟地址
*/
BYTE *RvaToVa(_In_ BYTE *lpImageBase, _In_ DWORD dwRva);

/*
 - 描述
    计算对齐后的数据大小
 - 输入参数
    dwSize: 原数据大小
    dwAlign: 对齐值
 - 返回值
    对齐后的数据大小
*/
DWORD AlignSize(_In_ DWORD dwSize, _In_ DWORD dwAlign);