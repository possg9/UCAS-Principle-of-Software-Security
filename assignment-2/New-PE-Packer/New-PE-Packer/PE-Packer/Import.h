/*****************************
 - 文件名称
    Import.h, Import.c
 - 描述
    计算变形后的导入表大小
    导入表变形
    清空原始导入表
******************************/
#pragma once
#include "Image.h"

/*------------------------- 新导入表结构 -------------------------
    FirstThunk: DWORD
    Dll名称长度: BYTE, Dll名称: STRING
    函数数量: DWORD
    函数(1)名称长度: BYTE, 函数(1)名称: STRING
    函数(2)名称长度: BYTE, 函数(2)名称: STRING
    ...
    若函数名称长度字段为0x00, 则后续DWORD大小保存函数序号. 即:
    0x00: BYTE, 函数序号: DWORD
    所有名称长度包含'\0'结束符
----------------------------------------------------------------*/

/*
 - 描述
    计算变形后的导入表大小
 - 输入参数
    lpImageInfo: PE映像信息
 - 返回值
    变形后的导入表大小
*/
DWORD CalcNewImpTabSize(_In_ PE_IMAGE_INFO *lpImageInfo);

/*
 - 描述
    导入表变形
 - 输入参数
    lpImageInfo: PE映像信息
    lpBuffer: 存储新导入表的缓冲区, 可为NULL
    dwBufSize: 缓冲区大小
 - 返回值
    变形后的导入表大小
 - 备注
    可将lpBuffer设为NULL, 并根据返回值大小申请缓冲区
*/
DWORD TransformImpTab(_In_ PE_IMAGE_INFO *lpImageInfo,
    _Out_writes_bytes_to_opt_(dwBufSize, return) BYTE *lpBuffer, _In_ DWORD dwBufSize);

/*
 - 描述
    清空原始导入表
 - 输入参数
    lpImageInfo: PE映像信息
*/
void ClearImpTab(_In_ PE_IMAGE_INFO *lpImageInfo);