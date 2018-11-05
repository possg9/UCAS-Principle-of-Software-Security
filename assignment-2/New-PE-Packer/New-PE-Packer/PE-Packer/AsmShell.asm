; 1. Right click this file and open "Properties" -> "General" page
;    Set "Excluded From Build" to "No"
;    Set "Item Type" to "Custom Build Tool"
;    Close "Properties" page
;
; 2. Right click this file and open "Properties" -> "Custom Build Tool" page
;    Set "Command Line" to "ml /c /coff /Fo $(SolutionDir)$(ProjectName)\$(Configuration)\%(FileName).obj $(SolutionDir)$(ProjectName)\%(FileName).asm"
;    Set "Outputs" to "$(SolutionDir)$(ProjectName)\$(Configuration)\%(FileName).obj"
;
; 3. Right click project and open "Properties" -> "Linker" -> "Advanced" page
;    Set "Image Has Safe Exception Handlers" to "No (/SAFESEH:NO)"

;    外壳分为三个部分:
;        第一段 (初始化段)
;            - 解密并加载后续代码及数据
;        --------------------------------
;        第二段 (核心段)
;            - 解密节区数据
;            - 初始化原导入表
;            - 重定位
;            - 初始化TLS
;        第三段 (数据段)
;            - 变形后的原导入表数据
;        --------------------------------
;    其中只有第一段在PE文件中以明文存储

.586p
.model flat, stdcall
option casemap:none

include windows.inc

; 导出数据, 用于地址定位及数据存储
public  Begin               ; 基地址
public  ImpTabBegin         ; 导入表起始地址
public  ImpTabEnd           ; 导入表结束地址
public  InitBegin           ; 第一段(初始化段)起始地址
public  InitEnd             ; 第一段(初始化段)结束地址
public  ShellBegin          ; 第二段(核心段)起始地址
public  ShellEnd            ; 第二段(核心段)结束地址
public  InitData            ; 加密段信息
public  OriginData          ; 原始PE文件的相关信息

assume fs: nothing

; - 描述
;    数据解密
; - 输入参数
;    lpSrc: 原数据地址
;    dwSize: 数据大小
;    lpDest: 输出数据地址
DecryData               proto   lpSrc:dword, lpDest:dword, dwSize:dword

; - 描述
;    修改节区内存保护属性
; - 输入参数
;    lpVirtualProtect: VirtualProtect函数地址
;    hModule: PE映像基地址
;    lpNewProtect: DWORD数组，依次保存每个节区的新内存保护属性
; - 输出参数
;    lpOldProtect: DWORD数组，依次保存每个节区的原内存保护属性
SetSectionProtect       proto   lpVirtualProtect:dword, hModule:dword, lpNewProtect:dword, lpOldProtect:dword

; - 描述
;    获取节区表起始地址及节区数量
; - 输入参数
;    hModule: PE映像基地址
; - 输出参数
;    ecx: 节区数量
; - 返回值
;    节区表起始地址
GetSectionHeader        proto   hModule:dword

; 保存外壳加密段的信息
INIT_DATA       struct
    dwShellPackOffset   dword       ?       ; 数据偏移 (相对于外壳第一段基地址)
    dwShellPackSize     dword       ?       ; 数据大小
INIT_DATA       ends

; 保存原始PE文件的相关信息
ORIGIN_DATA     struct
    dwEntryPoint        dword       ?               ; 代码入口点
    dwImpTabOffset      dword       ?               ; 变形后的原导入表偏移 (相对于外壳第二段基地址)
    dwRelocTabRva       dword       ?               ; 重定位表RVA
    dwTlsTabRva         dword       ?               ; TLS表RVA
    dwImageBase         dword       ?               ; 原始映像基地址
    szSecEncryInfo      dword       0A0h dup (?)    ; 节区加密信息
ORIGIN_DATA     ends


.code
Begin           label   dword       ; 基地址
; --------------------------- 第一段 ---------------------------
InitBegin       label   dword       ; 第一段(初始化段)起始地址
    pushad
    call    _Init
    
    ImpTabBegin     label   dword       ; 导入表起始地址
    ; 所有RVA类型数据仅保存其相对于导入表起始地址的偏移, 后续的调整工作在安装外壳时进行
    ImportTable     IMAGE_IMPORT_DESCRIPTOR     <<FirstAddr - ImpTabBegin>, 0, 0, DllName - ImpTabBegin, FirstAddr - ImpTabBegin>
                    IMAGE_IMPORT_DESCRIPTOR     <<0>, 0, 0, 0, 0>
        
    FirstAddr       IMAGE_THUNK_DATA            <<FirstFunc - ImpTabBegin>>
    SecondAddr      IMAGE_THUNK_DATA            <<SecondFunc - ImpTabBegin>>
    ThirdAddr       IMAGE_THUNK_DATA            <<ThirdFunc - ImpTabBegin>>
                    IMAGE_THUNK_DATA            <<0>>
    
    DllName         DB      'Kernel32.dll', 0
    
    ; IMAGE_IMPORT_BY_NAME
    FirstFunc       DW      0
                    DB      'GetProcAddress', 0
    SecondFunc      DW      0
                    DB      'GetModuleHandleA', 0
    ThirdFunc       DW      0
                    DB      'LoadLibraryA', 0
    ImpTabEnd       label   dword       ; 导入表结束地址

    InitData            INIT_DATA   <>      ; 加密段的信息
    
    VirtualAllocName    DB          'VirtualAlloc', 0
    VirtualAllocAddr_I  DD          0       ; VirtualAlloc函数地址
    ShellBase           DD          0       ; 解密后的第二段基地址
    
_Init:
    pop     ebp     ; 代码重定位
    sub     ebp, ImpTabBegin - InitBegin    ; ebp保存第一段基地址
    
    ; 获取VirtualAlloc函数地址
    lea     esi, [ebp + (DllName - InitBegin)]
    push    esi
    call    dword ptr [ebp + (SecondAddr - InitBegin)]
    lea     esi, [ebp + (VirtualAllocName - InitBegin)]
    push    esi
    push    eax
    call    dword ptr [ebp + (FirstAddr - InitBegin)]
    mov     dword ptr [ebp + (VirtualAllocAddr_I - InitBegin)], eax
    
    ; 申请内存空间, 解密并加载后续代码及数据  
    push    PAGE_EXECUTE_READWRITE
    push    MEM_COMMIT or MEM_RESERVE
    push    dword ptr [ebp + (InitData + INIT_DATA.dwShellPackSize - InitBegin)]
    push    NULL
    call    dword ptr [ebp + (VirtualAllocAddr_I - InitBegin)]
    mov     dword ptr [ebp + (ShellBase - InitBegin)], eax
    
    ; 解密数据
    mov     ecx, dword ptr [ebp + (InitData + INIT_DATA.dwShellPackSize - InitBegin)]
    push    ecx
    push    eax
    mov     ebx, dword ptr [ebp + (InitData + INIT_DATA.dwShellPackOffset - InitBegin)]
    add     ebx, ebp
    push    ebx
    call    DecryData
    
    ; 构造跳转指令, 执行第二段代码
    push    ebp
    mov     eax, dword ptr [ebp + (ShellBase - InitBegin)]
    mov     edx, ebp
    add     edx, (_JmpShell - InitBegin) + sizeof(BYTE) * 5
    sub     eax, edx
    mov     dword ptr [ebp + (_JmpShell - InitBegin) + sizeof(BYTE)], eax
_JmpShell:
    DB      0E9h, 0FFh, 0FFh, 0FFh, 0FFh    ; jmp ShellBase

; 数据解密
DecryData       proc    lpSrc:dword, lpDest:dword, dwSize:dword
    pushad
    mov     ecx, dwSize
    mov     esi, lpSrc
    mov     edi, lpDest
    .while  ecx != 0
        lodsb
        xor     al, 0FFh
        stosb
        dec     ecx
    .endw
    popad
    ret
DecryData       endp
InitEnd         label   dword       ; 第一段(初始化段)结束地址

; --------------------------- 第二段 ---------------------------
ShellBegin      label   dword       ; 第二段(核心段)起始地址
    call    _Next
_Next:
    pop     edx     ; 代码重定位
    sub     edx, _Next - ShellBegin     ; edx保存第二段基地址
    pop     ebp                         ; ebp保存第一段基地址
    
    ; 将第一段中的部分数据拷贝至第二段
    mov     ecx, 3
    lea     esi, [ebp + (FirstAddr - InitBegin)]
    lea     edi, [edx + (GetProcAddressAddr - ShellBegin)]
    cld
    rep     movsd
    
    lea     eax, [ebp + (DecryData - InitBegin)]
    mov     dword ptr [edx + (DecryDataAddr - ShellBegin)], eax
    mov     eax, dword ptr [ebp + (VirtualAllocAddr_I - InitBegin)]
    mov     dword ptr [edx + (VirtualAllocAddr - ShellBegin)], eax
    mov     ebp, edx    ; ebp保存第二段基地址
    
    ; 获取VirtualProtect函数地址
    lea     esi, [ebp + (Kernel32Name - ShellBegin)]
    push    esi
    call    dword ptr [ebp + (GetModuleHandleAddr - ShellBegin)]
    lea     esi, [ebp + (VirtualProtectName - ShellBegin)]
    push    esi
    push    eax
    call    dword ptr [ebp + (GetProcAddressAddr - ShellBegin)]
    mov     dword ptr [ebp + (VirtualProtectAddr - ShellBegin)], eax
    
    ; 获取PE映像的实际加载地址
    push    NULL
    call    dword ptr [ebp + (GetModuleHandleAddr - ShellBegin)]
    mov     dword ptr [ebp + (hModule - ShellBegin)], eax
    
    ; --------------- 节区加密信息结构 ---------------
    ; 节区(1)RVA: DWORD, 节区(1)加密大小: STRING
    ; 节区(2)RVA: DWORD, 节区(2)加密大小: STRING
    ; ...
    ; ------------------------------------------------

    ; 设置节区内存保护属性为可读、可写、可执行
    mov     ecx, lengthof SecProtects
    mov     eax, PAGE_EXECUTE_READWRITE
    lea     edi, [ebp + (SecProtects - ShellBegin)]
    cld
    rep     stosd
    
    lea     esi, [ebp + (SecProtects - ShellBegin)]
    lea     edi, [ebp + (SecProtects - ShellBegin)]
    push    edi
    push    esi
    push    dword ptr [ebp + (hModule - ShellBegin)]
    push    dword ptr [ebp + (VirtualProtectAddr - ShellBegin)]
    call    SetSectionProtect
    
    ; 解密节区数据
    mov     edx, OriginData + ORIGIN_DATA.szSecEncryInfo - ShellBegin
    mov     eax, dword ptr [ebp + edx]
    .while  eax != NULL
        mov     esi, dword ptr [ebp + (hModule - ShellBegin)]
        add     esi, eax    ; 数据地址
        mov     edi, esi
        mov     ecx, dword ptr [ebp + edx + sizeof(DWORD)]  ; 数据大小
        push    ecx
        push    edi
        push    esi
        call    dword ptr [ebp + (DecryDataAddr - ShellBegin)]
        add     edx, sizeof(DWORD) * 2
        mov     eax, dword ptr [ebp + edx]
    .endw
    
    ; ------------------------- 新导入表结构 -------------------------
    ;   FirstThunk: DWORD
    ;   Dll名称长度: BYTE, Dll名称: STRING
    ;   函数数量: DWORD
    ;   函数(1)名称长度: BYTE, 函数(1)名称: STRING
    ;   函数(2)名称长度: BYTE, 函数(2)名称: STRING
    ;   ...
    ;   若函数名称长度字段为0x00, 则后续DWORD大小保存函数序号. 即:
    ;   0x00: BYTE, 函数序号: DWORD
    ;   所有名称长度包含'\0'结束符
    ; ----------------------------------------------------------------
    
    ; 初始化原导入表
    mov     esi, dword ptr [ebp + (OriginData + ORIGIN_DATA.dwImpTabOffset - ShellBegin)]
    add     esi, ebp
    mov     edi, dword ptr [esi]    ; FirstThunk
    .while  edi != NULL
        add     edi, dword ptr [ebp + (hModule - ShellBegin)]
        add     esi, sizeof(DWORD) + sizeof(BYTE)   ; Dll名称
        ; 加载指定Dll
        push    esi
        call    dword ptr [ebp + (GetModuleHandleAddr - ShellBegin)]
        .if     eax == NULL
            push    esi
            call    dword ptr [ebp + (LoadLibraryAddr - ShellBegin)]
        .endif
        mov     edx, eax
        movzx   ecx, byte ptr [esi - sizeof(BYTE)]
        add     esi, ecx
        mov     ecx, dword ptr [esi]    ; 导入函数数量
        add     esi, sizeof(DWORD)
        .while  ecx != 0
            push    ecx
            push    edx
            movzx   ebx, byte ptr [esi]     ; 函数名称长度
            inc     esi
            .if     ebx == 0
                    ; 以序号导入
                    mov     ebx, dword ptr [esi]    ; 函数序号
                    add     esi, sizeof(DWORD)
                    push    ebx                       
            .else
                    ; 以名称导入
                    push    esi     ; 函数名称
                    add     esi, ebx
            .endif
            push    edx
            ; 获得函数地址, 保存至IAT
            call    dword ptr [ebp + (GetProcAddressAddr - ShellBegin)]
            mov     dword ptr [edi], eax
            add     edi, sizeof(DWORD)
            pop     edx
            pop     ecx
            dec     ecx
        .endw
        mov     edi, dword ptr [esi]
    .endw
    
    ; 代码重定位
    mov     esi, dword ptr [ebp + (OriginData + ORIGIN_DATA.dwRelocTabRva - ShellBegin)]
    mov     ebx, dword ptr [ebp + (hModule - ShellBegin)]
    .if     esi != NULL
        add     esi, ebx
        assume  esi: ptr IMAGE_BASE_RELOCATION
        mov     edi, [esi].VirtualAddress
        .while  edi != NULL
            mov     ecx, [esi].SizeOfBlock
            sub     ecx, sizeof(IMAGE_BASE_RELOCATION)
            shr     ecx, 1     
            add     esi, sizeof(IMAGE_BASE_RELOCATION)
            .while  ecx != 0
                xor     eax, eax
                mov     ax, word ptr [esi]
                and     ax, 0F000h
                shr     ax, 12
                ; 判断重定位类型
                .if     ax == IMAGE_REL_BASED_HIGHLOW
                    xor     eax, eax
                    mov     ax, word ptr [esi]
                    and     ax, 0FFFh       ; 获取重定位偏移
                    push    edi
                    add     edi, eax
                    add     edi, ebx
                    ; 调整地址
                    mov     eax, dword ptr [edi]
                    sub     eax, dword ptr [ebp + (OriginData + ORIGIN_DATA.dwImageBase - ShellBegin)]
                    add     eax, ebx
                    mov     dword ptr [edi], eax
                    pop     edi
                .endif
                add     esi, sizeof(WORD)
                dec     ecx
            .endw
            mov     edi, [esi].VirtualAddress
        .endw
        assume  esi: nothing
    .endif
    
    ; 初始化TLS
    mov     esi, dword ptr [ebp + (OriginData + ORIGIN_DATA.dwTlsTabRva - ShellBegin)]
    mov     ebx, dword ptr [ebp + (hModule - ShellBegin)]
    .if     esi != NULL
        add     esi, ebx
        assume  esi: ptr IMAGE_TLS_DIRECTORY
        mov     edi, [esi].AddressOfCallBacks
        mov     eax, dword ptr [edi]
        .while  eax != NULL
            ; 调用TLS回调函数
            push    NULL
            push    DLL_PROCESS_ATTACH
            push    ebx
            call    eax
            add     edi, sizeof(DWORD)
            mov     eax, dword ptr [edi]
        .endw
        assume  esi: nothing
    .endif
    
    ; 还原节区内存保护属性
    lea     esi, [ebp + (SecProtects - ShellBegin)]
    lea     edi, [ebp + (SecProtects - ShellBegin)]
    push    edi
    push    esi
    push    dword ptr [ebp + (hModule - ShellBegin)]
    push    dword ptr [ebp + (VirtualProtectAddr - ShellBegin)]
    call    SetSectionProtect
    
    ; 跳转至原始代码入口点
    mov     eax, dword ptr [ebp + (OriginData + ORIGIN_DATA.dwEntryPoint - ShellBegin)]
    add     eax, dword ptr [ebp + (hModule - ShellBegin)]
    mov     dword ptr [ebp + (_RetOEP - ShellBegin) + sizeof(BYTE)], eax
    popad
_RetOEP:
    DB      68h, 0FFh, 0FFh, 0FFh, 0FFh     ; push dwEntryPoint
    ret
    
; 获取节区表起始地址及节区数量
GetSectionHeader        proc    hModule:dword
    mov     eax, hModule
    assume  eax: ptr IMAGE_DOS_HEADER
    add     eax, [eax].e_lfanew
    assume  eax: ptr IMAGE_NT_HEADERS
    movzx   ecx, [eax].FileHeader.NumberOfSections      ; ecx保存节区数量
    add     ax, [eax].FileHeader.SizeOfOptionalHeader
    add     eax, sizeof(DWORD)
    add     eax, sizeof(IMAGE_FILE_HEADER)
    assume  eax: nothing
    ret
GetSectionHeader        endp

; 修改节区内存保护属性
SetSectionProtect       proc   lpVirtualProtect:dword, hModule:dword, lpNewProtect:dword, lpOldProtect:dword
    pushad
    push    hModule
    call    GetSectionHeader
    mov     ebx, eax            ; ebx为节区表起始地址，ecx为节区数量
    assume  ebx: ptr IMAGE_SECTION_HEADER
    mov     esi, lpNewProtect
    mov     edi, lpOldProtect
    xor     edx, edx
    .while  edx != ecx
        pushad
        lea     eax, [edi + sizeof(DWORD) * edx]
        push    eax
        mov     eax, dword ptr [esi + sizeof(DWORD) * edx]
        push    eax
        push    [ebx].Misc.VirtualSize
        mov     eax, [ebx].VirtualAddress
        add     eax, hModule
        push    eax
        call    lpVirtualProtect
        popad
        add     ebx, sizeof(IMAGE_SECTION_HEADER)
        inc     edx
    .endw
    assume  ebx: nothing
    popad
    ret
SetSectionProtect       endp
    
    OriginData              ORIGIN_DATA     <>      ; 原始PE文件的相关信息
    
    ; 以下三个变量的先后顺序同外壳导入表中的函数顺序相同，不能更改，以方便数据拷贝
    GetProcAddressAddr      DD              0       ; GetProcAddress函数地址
    GetModuleHandleAddr     DD              0       ; GetModuleHandle函数地址
    LoadLibraryAddr         DD              0       ; LoadLibrary函数地址
    
    VirtualAllocAddr        DD              0       ; VirtualAlloc函数地址
    VirtualProtectAddr      DD              0       ; VirtualProtect函数地址
    DecryDataAddr           DD              0       ; DecryData函数地址
    hModule                 DD              0       ; PE映像的实际加载地址
    SecProtects             DD              020h dup (?)    ; 节区内存保护属性
    
    Kernel32Name            DB              'Kernel32.dll', 0
    VirtualProtectName      DB              'VirtualProtect', 0
    
ShellEnd        label   dword       ; 第二段(核心段)结束地址
end