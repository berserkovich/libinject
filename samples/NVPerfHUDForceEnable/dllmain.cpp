
#include "libinject/libinject.h"
#include "MinHook.h"

#include <Shellapi.h>

#include <cassert>
#include <string>
#include <vector>

static std::string g_moduleFilenameUtf8;

static BOOL (WINAPI *OrigCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = NULL;
static BOOL WINAPI HookedCreateProcessA(
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation
    )
{
    dwCreationFlags |= CREATE_SUSPENDED;
    BOOL result = OrigCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles
                                    , dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( result != FALSE )
    {
        LIBINJECT_Inject(lpProcessInformation->hProcess, g_moduleFilenameUtf8.c_str());
        ::ResumeThread(lpProcessInformation->hThread);
    }
    return result;
}

static BOOL (WINAPI *OrigCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = NULL;
static BOOL WINAPI HookedCreateProcessW(
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation
    )
{
    dwCreationFlags |= CREATE_SUSPENDED;
    BOOL result = OrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles
                                    , dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( result != FALSE )
    {
        LIBINJECT_Inject(lpProcessInformation->hProcess, g_moduleFilenameUtf8.c_str());
        ::ResumeThread(lpProcessInformation->hThread);
    }
    return result;
}

static std::wstring GetModulePath( HMODULE _hModule )
{
  std::vector<wchar_t> modulePath(MAX_PATH);

  // Try to get the executable path with a buffer of MAX_PATH characters.
  DWORD result = ::GetModuleFileNameW(_hModule, &(modulePath[0]), static_cast<DWORD>(modulePath.size()));

  // As long the function returns the buffer size, it is indicating that the buffer
  // was too small. Keep enlarging the buffer by a factor of 2 until it fits.
  while(result == modulePath.size()) 
  {
    modulePath.resize(modulePath.size() * 2);
    result = ::GetModuleFileNameW(_hModule, &(modulePath[0]), static_cast<DWORD>(modulePath.size()));
  }

  if( result == 0 )
  {
      return std::wstring();
  }

  // We've got the path, construct a standard string from it
  return std::wstring(modulePath.begin(), modulePath.begin() + result);
}

void WstrToUtf8( const std::wstring& _wstr, std::string* _utf8 )
{
    assert( _utf8 != NULL );
    if( _utf8 != NULL )
    {
        const wchar_t* cwstr = _wstr.c_str();
        int size = ::WideCharToMultiByte( CP_UTF8, 0, cwstr, -1, 0, 0, 0, 0 );
        std::vector<char> buffer(size);
        ::WideCharToMultiByte( CP_UTF8, 0, cwstr, -1, &(buffer[0]), size, NULL, NULL );
        _utf8->assign( &(buffer[0]) );
    }
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )  
{
    if( fdwReason == DLL_PROCESS_ATTACH )
    {
        //::MessageBoxA(NULL, "Attach", "inject", MB_OK);
        if( MH_Initialize() != MH_OK )
        {
            return FALSE;
        }

	    if( MH_CreateHook(&CreateProcessA, &HookedCreateProcessA, reinterpret_cast<void**>(&OrigCreateProcessA)) != MH_OK )
	    {
		    return FALSE;
	    }

	    if( MH_EnableHook(&CreateProcessA) != MH_OK )
	    {
		    return FALSE;
	    }

	    if( MH_CreateHook(&CreateProcessW, &HookedCreateProcessW, reinterpret_cast<void**>(&OrigCreateProcessW)) != MH_OK )
	    {
		    return FALSE;
	    }

	    if( MH_EnableHook(&CreateProcessW) != MH_OK )
	    {
		    return FALSE;
	    }

        std::wstring moduleFilename = GetModulePath(hinstDLL);
        WstrToUtf8(moduleFilename, &g_moduleFilenameUtf8);
    }
    return TRUE;
}
