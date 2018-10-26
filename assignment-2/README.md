# UCAS-Principle-of-Software-Security
软件安全原理-第二次作业
## 作业内容
- 恶意应用编写，以了解常见恶意应用的行为及实现方法
- 目标操作系统：win7，编写语言：C/C++
- 相关功能
  - 进程隐藏
  - 键盘记录(keylogger)
  - 永久驻留
  - 注册表/信息采集
  - 混淆


## 相关资料

- Framework for building Windows malware, written in C++
  包括操作注册表，永久驻留，获取管理员权限？，隐藏应用，keylogger
  https://github.com/richkmeli/Richkware

- A Stealthy Trojan Spyware (keylogger-spyware-malware-worm-spy-virus-fud-undetectable-computer-windows-pc-c-c++)
  logs user's data, sends data through Transmit.exe, infects portable drive
  https://github.com/MinhasKamal/TrojanCockroach

- An obfuscation tool for Windows which instruments the Windows Loader into acting as an unpacking engine
  https://github.com/nickcano/RelocBonus

- Source codes of malwares, stress tests etc. for computer.
  https://github.com/SKocur/Malware-Collection

- C++ Windows Mining Malware
  https://github.com/BitTheByte/Windows-malware

- Ways for malwares to gain persistence in Windows.
  https://github.com/zhubrain/Windows_persistenc

----

- 进程隐藏：
  https://www.cnblogs.com/17bdw/p/6527998.html
  https://www.cnblogs.com/devc/p/4092837.html
  https://blog.csdn.net/Willon_tom/article/details/5148217?utm_source=blogxgwz1
  https://tinytracer.com/archives/rootkit初探-进程隐藏与混淆
- 远程控制
  https://blog.csdn.net/sumkee911/article/details/53885255
- 注册表：
  https://blog.csdn.net/enjoy5512/article/details/51842960

---

- 键盘记录
  https://github.com/vim2meta/keylogger
- windows恶意样本源码
  https://github.com/ulexec/WindowsMalwareSourceCode
- 恶意功能较全的实现
  https://github.com/AHXR/ghost
- An Easy tool to Generate Backdoor for bypass AV and Easy Tool For Post exploitation attack like browser attack,dll . This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac .
  https://github.com/Screetsec/TheFatRat