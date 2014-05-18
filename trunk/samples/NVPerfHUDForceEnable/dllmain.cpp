#define CINTERFACE

#include "libinject/libinject.h"
#include "MinHook.h"

#include <Shellapi.h>

#include <algorithm>
#include <cassert>
#include <string>
#include <vector>

#include <d3d9.h>

namespace 
{
    std::string g_moduleFilenameUtf8;

    HANDLE hInjectedProcessMainThread = NULL;
    DWORD injectedProcessId = 0;

    void HookD3D9( HMODULE hDll );

    DWORD (WINAPI* OrigResumeThread)(HANDLE);
    DWORD WINAPI HookedResumeThread( HANDLE hThread )
    {
        if( hThread == hInjectedProcessMainThread )
        {
            LIBINJECT_Inject(injectedProcessId, g_moduleFilenameUtf8.c_str());
        }
        return OrigResumeThread(hThread);
    }

    BOOL (WINAPI *OrigCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = NULL;
    BOOL WINAPI HookedCreateProcessA(
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
	    bool hasSuspendedFlag = ((dwCreationFlags & CREATE_SUSPENDED) != 0);
        dwCreationFlags |= CREATE_SUSPENDED;
        BOOL result = OrigCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles
                                        , dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        if( result != FALSE
            && hasSuspendedFlag )
        {
            // we can't inject now, because NVPerfHUD uses MS Detours to inject its hooks
            // and MS Detours patches dll import table to load new dll upon process initialization
            // if we inject now injection will trigger process initialization and dll import table patch will come too late
            // so we just remember what process is going to start and inject it on ResumeThread after MS Detours did its job
            injectedProcessId = lpProcessInformation->dwProcessId;
            hInjectedProcessMainThread = lpProcessInformation->hThread;
        }

        return result;
    }

    BOOL (WINAPI *OrigCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = NULL;
    BOOL WINAPI HookedCreateProcessW(
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
	    bool hasSuspendedFlag = ((dwCreationFlags & CREATE_SUSPENDED) != 0);
        dwCreationFlags |= CREATE_SUSPENDED;
        BOOL result = OrigCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles
                                        , dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        if( result != FALSE
            && hasSuspendedFlag )
        {
            injectedProcessId = lpProcessInformation->dwProcessId;
            hInjectedProcessMainThread = lpProcessInformation->hThread;
        }

        return result;
    }

    HMODULE (WINAPI* OrigLoadLibraryW)(LPCWSTR) = NULL;
    HMODULE WINAPI HookedLoadLibraryW(
        __in LPCWSTR lpLibFileName)
    {
        HMODULE hModule = OrigLoadLibraryW(lpLibFileName);
        if( hModule != NULL )
        {
            HookD3D9(::GetModuleHandleW(L"d3d9.dll"));
        }
        return hModule;
    }

    HRESULT (WINAPI* OrigDirect3DCreateDevice)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice9**) = NULL;
    HRESULT WINAPI HookedDirect3DCreateDevice(IDirect3D9* This, UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow, DWORD BehaviorFlags, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface)
    {
        UINT adapterOverride = Adapter;
        D3DDEVTYPE deviceTypeOverride = DeviceType;
        UINT adapterCount = This->lpVtbl->GetAdapterCount(This);
        for( UINT adapterIndex = 0; adapterIndex < adapterCount; ++adapterIndex) 
        {
            D3DADAPTER_IDENTIFIER9 adapterIdentifier;
            HRESULT hResult = This->lpVtbl->GetAdapterIdentifier(This, adapterIndex, 0, &adapterIdentifier);
            if( std::strstr(adapterIdentifier.Description, "PerfHUD") != 0)
            {
                adapterOverride = adapterIndex;
                deviceTypeOverride = D3DDEVTYPE_REF;
                break;
            }
        }

        return OrigDirect3DCreateDevice(This, adapterOverride, deviceTypeOverride, hFocusWindow, BehaviorFlags, pPresentationParameters, ppReturnedDeviceInterface);
    }

    IDirect3D9* (WINAPI *OrigDirect3DCreate9)(UINT) = NULL;
    IDirect3D9* WINAPI HookedDirect3DCreate9( UINT SDKVersion )
    {
        IDirect3D9* pD3D9 = OrigDirect3DCreate9(SDKVersion);

        if( pD3D9 != NULL )
        {
            MH_CreateHook(pD3D9->lpVtbl->CreateDevice, &HookedDirect3DCreateDevice, reinterpret_cast<void**>(&OrigDirect3DCreateDevice));
            MH_EnableHook(pD3D9->lpVtbl->CreateDevice);
        }
        return pD3D9;
    }

    void HookD3D9( HMODULE hDll )
    {
        if( hDll == NULL )
        {
            return;
        }

        FARPROC pDirect3DCreate9 = ::GetProcAddress(hDll, "Direct3DCreate9");
        if( pDirect3DCreate9 == NULL )
        {
            return;
        }

        if( MH_CreateHook(pDirect3DCreate9, &HookedDirect3DCreate9, reinterpret_cast<void**>(&OrigDirect3DCreate9)) != MH_OK )
        {
            return;
        }

        if( MH_EnableHook(pDirect3DCreate9) != MH_OK )
        {
            return;
        }
    }

    std::wstring GetModulePath( HMODULE _hModule )
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
}   // namespace

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )  
{
    if( fdwReason == DLL_PROCESS_ATTACH )
    {
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

        if( MH_CreateHook(&ResumeThread, &HookedResumeThread, reinterpret_cast<void**>(&OrigResumeThread)) != MH_OK )
        {
            return FALSE;
        }

        if( MH_EnableHook(&ResumeThread) != MH_OK )
        {
            return FALSE;
        }

        if( MH_CreateHook(&LoadLibraryW, &HookedLoadLibraryW, reinterpret_cast<void**>(&OrigLoadLibraryW)) != MH_OK )
        {
            return FALSE;
        }

        if( MH_EnableHook(&LoadLibraryW) != MH_OK )
        {
            return FALSE;
        }

        HookD3D9(::GetModuleHandleW(L"d3d9.dll"));

        std::wstring moduleFilename = GetModulePath(hinstDLL);
        WstrToUtf8(moduleFilename, &g_moduleFilenameUtf8);
    }
    return TRUE;
}
