# 进程隐藏

#### How to use

两个核心部件的作用：加载sys文件依赖dkom.exe，进程隐藏依赖Hide.sys。

1. Hide.sys需要放到C:/HideProcess文件夹下，如果C盘下没有这个目录，先新建这个目录。
2. 管理员权限运行命令行，使用命令"dkom.exe group9.exe" [loader process] 即可。

如何合并：Hide.sys放到C:/HideProcess文件夹下，dkom.exe放到工程根目录下，在main函数里面直接写命令行语句"system("dkom.exe group9.exe");"。注意最后的程序要在管理员权限下运行，否则内核模块Hide.sys没有权限加载。

### Reference

http://www.landhb.me/posts/v9eRa/a-basic-windows-dkom-rootkit-pt-1/

### Limitations

不能绕过 PatchGuard 或 驱动签名认证.
在win7 x86 下测试.

