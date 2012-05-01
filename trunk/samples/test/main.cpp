
#include "libinject/libinject.h"

int main( int _argc, char* _argv[] )
{
    const char* injectLib[] = { "testdll.dll", NULL };
    LIBINJECT_PROCESS hProcess = NULL;
    int result = LIBINJECT_StartInjected(_argv[1], NULL, injectLib, &hProcess);
    ::WaitForSingleObject(hProcess, INFINITE);
    return 0;
}
