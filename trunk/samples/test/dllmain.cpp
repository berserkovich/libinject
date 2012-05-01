#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )  
{
    if( fdwReason == DLL_PROCESS_ATTACH )
    {
        ::MessageBoxA(NULL, "Hello from injected dll", "injected.dll", MB_OK);
    }
    return TRUE;
}
#endif
