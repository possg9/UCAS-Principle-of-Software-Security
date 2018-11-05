/***************************
 - 文件名称
    Section.h, Section.c
 - 描述
    加密节区数据
    在尾部增加节区
    计算加密信息大小
    清空节区名称
****************************/
#pragma once
#include "Image.h"

/*
 - 描述
    在PE映像尾部增加节区
 - 输入参数
    lpImageInfo: PE映像信息
    lpName: 新节区名称, 可为NULL
    dwSize: 新节区大小
 - 输出参数
    lpNewSecHeader: 新节区表项
 - 返回值
    节区数量
*/
WORD AppendSection(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _In_reads_or_z_opt_(IMAGE_SIZEOF_SHORT_NAME) const char *lpName,
    _In_ DWORD dwSize, _Out_ IMAGE_SECTION_HEADER *lpNewSecHeader);

/*--------------- 节区加密信息结构 ---------------
    节区(1)RVA: DWORD, 节区(1)加密大小: STRING
    节区(2)RVA: DWORD, 节区(2)加密大小: STRING
    ...
------------------------------------------------*/

/*
 - 描述
    计算节区加密信息的大小
 - 输入参数
    lpImageInfo: PE映像信息
 - 返回值
    节区加密信息的大小
*/
DWORD CalcEncryInfoSize(_In_ const PE_IMAGE_INFO *lpImageInfo);

/*
 - 描述
    加密节区数据
 - 输入参数
    lpImageInfo: PE映像信息
    lpInfoBuffer: 存储加密信息的缓冲区, 可为NULL
    dwBufSize: 缓冲区大小
 - 返回值
    节区加密信息的大小
 - 备注
    可将lpInfoBuffer设为NULL, 并根据返回值大小申请缓冲区
*/
DWORD EncrySection(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _Out_writes_bytes_to_opt_(dwBufSize, return) BYTE *lpInfoBuffer, 
    _In_ DWORD dwBufSize);
    
/*
 - 描述
    清空节区名称
 - 输入参数
    lpImageInfo: PE映像信息
*/
void ClearSectionName(_In_ PE_IMAGE_INFO *lpImageInfo);