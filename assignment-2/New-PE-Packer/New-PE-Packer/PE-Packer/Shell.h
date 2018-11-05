/***********************
 - 文件名称
    Shell.h, Shell.c
 - 描述
    安装外壳
************************/
#pragma once
#include "Image.h"

/*
    外壳分为三个部分:
        第一段 (初始化段)
            - 解密并加载后续代码及数据
        --------------------------------
        第二段 (核心段)
            - 解密节区数据
            - 初始化原导入表
            - 重定位
            - 初始化TLS
        第三段 (数据段)
            - 变形后的原导入表数据
        --------------------------------
    其中只有第一段在PE文件中以明文存储
*/

/*
 - 描述
    计算外壳总大小
 - 输入参数
    dwNewImpTabSize: 变形后的导入表大小
 - 返回值
    外壳总大小
*/
DWORD CalcShellSize(_In_ DWORD dwNewImpTabSize);

/*
 - 描述
    安装外壳
 - 输入参数
    lpImageInfo: PE映像信息
    lpNewImpTab: 变形后的导入表
    dwNewImpTabSize: 变形后的导入表大小
    lpSecEncryInfo: 节区加密信息
    dwSecEncryInfoSize: 节区加密信息大小
 - 返回值
    安装成功, 则返回true; 否则返回false
*/
bool SetupShell(_In_ PE_IMAGE_INFO *lpImageInfo, 
    _In_ const BYTE *lpNewImpTab,
    _In_ DWORD dwNewImpTabSize, 
    _In_ const BYTE *lpSecEncryInfo, 
    _In_ DWORD dwSecEncryInfoSize);

/*
 - 描述
    数据加密
 - 输入参数
    lpData: 数据地址
    dwSize: 数据大小
*/
void EncryData(_In_ BYTE *lpData, _In_ DWORD dwSize);