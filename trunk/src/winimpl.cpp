#include "libinject/libinject.h"

#include "winx86buffer.h"

#include <TlHelp32.h>

#include <algorithm> 
#include <cassert>
#include <cstring>
#include <vector>

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

static bool utf8_to_ucs2( const char* _utf8string, std::vector<wchar_t>* _ucs2string )
{
    assert(_utf8string);
    assert(_ucs2string);

    _ucs2string->reserve(std::strlen(_utf8string) + 1);

    while( *_utf8string != '\0' )
    {
        unsigned char byte0 = static_cast<unsigned char>(_utf8string[0]);
        if( byte0 < 0x80 )
        {
            _ucs2string->push_back(static_cast<wchar_t>(byte0));
            ++_utf8string;
        }
        else if( (byte0 & 0xE0) == 0xE0 )
        {
            unsigned char byte1 = static_cast<unsigned char>(_utf8string[1]);
            if( byte1 == 0 )
            {
                return false;
            }
            unsigned char byte2 = static_cast<unsigned char>(_utf8string[2]);
            if( byte2 == 0 )
            {
                return false;
            }

            _ucs2string->push_back(static_cast<wchar_t>((byte0 & 0x0F)<<12 | (byte1 & 0x3F)<<6 | (byte2 & 0x3F)));
            _utf8string += 3;
        }
        else if( (byte0 & 0xC0) == 0xC0 )
        {
            unsigned char byte1 = static_cast<unsigned char>(_utf8string[1]);
            if( byte1 == 0 )
            {
                return false;
            }

            _ucs2string->push_back(static_cast<wchar_t>((byte0 & 0x1F)<<6 | (byte1 & 0x3F)));
            _utf8string += 2;
        }
    }
    _ucs2string->push_back(L'\0');
    return true;
}

static bool createInjectionBuffer( const std::vector<wchar_t>& _libToInject, std::vector<unsigned char>* _injectionBuffer, DWORD* _endInstructionOffset )
{
    assert(_injectionBuffer);
    assert(_libToInject.empty() == false);
    assert(_endInstructionOffset);

    size_t codeBufferSize = sizeof(x86TemplateBuffer);
    size_t padSize = (4 - (codeBufferSize % 4));
    size_t dataOffset = codeBufferSize + padSize;
    *_endInstructionOffset = static_cast<DWORD>(codeBufferSize - 2);
    _injectionBuffer->resize(codeBufferSize + padSize + sizeof(x86TemplateBufferData) + _libToInject.size() * sizeof(wchar_t) + 4);
    std::vector<unsigned char>::iterator bufferWriteMarker = std::copy(&(x86TemplateBuffer[0]), &(x86TemplateBuffer[0]) + codeBufferSize, _injectionBuffer->begin());
    std::fill(bufferWriteMarker, bufferWriteMarker + padSize, 0xCC);    // pad data with INT3s
    bufferWriteMarker = std::copy(&(x86TemplateBufferData[0]), &(x86TemplateBufferData[0]) + sizeof(x86TemplateBufferData), bufferWriteMarker + padSize);
    std::copy(reinterpret_cast<const unsigned char*>(&(_libToInject[0])), reinterpret_cast<const unsigned char*>(&(_libToInject[0]) + _libToInject.size()), bufferWriteMarker);
    std::copy(reinterpret_cast<unsigned char*>(&dataOffset), reinterpret_cast<unsigned char*>(&dataOffset) + 4, _injectionBuffer->begin());
    return true;
}

int LIBINJECT_Inject( LIBINJECT_PROCESS _processHandle, const char* _libToInjectUtf8 )
{
    int error = LIBINJECT_OK;
    DWORD pid = ::GetProcessId(_processHandle);
    BOOL suspended = FALSE;
    BOOL attached = FALSE;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
    THREADENTRY32 te32;
    std::vector<HANDLE> threads;
    std::vector<wchar_t> libToInject;
    std::vector<wchar_t> libToInjectFullpath;
    std::vector<unsigned char> injectionBuffer;
    void* codecaveAddress = NULL;
    void* codecaveExecAddress = NULL;
    CONTEXT threadContext = { CONTEXT_ALL, 0 };
    CONTEXT currentContext = { CONTEXT_FULL, 0 };

    if( _libToInjectUtf8 == NULL )
    {
        error = LIBINJECT_INVALID_PARAM;
        goto exit_label;
    }

    if( utf8_to_ucs2(_libToInjectUtf8, &libToInject) == false )
    {
        error = LIBINJECT_INVALID_PARAM;
        goto exit_label;
    }

    DWORD fullnameLength = ::GetFullPathNameW(&(libToInject[0]), 0, NULL, NULL);
    if( fullnameLength == 0 )
    {
        error = LIBINJECT_INVALID_PARAM;
        goto exit_label;
    }
    libToInjectFullpath.resize(fullnameLength);
    ::GetFullPathNameW(&(libToInject[0]), libToInjectFullpath.size(), &(libToInjectFullpath[0]), NULL);

    attached = ::DebugActiveProcess(pid);
    if( attached == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    // break all the process threads
    suspended = ::DebugBreakProcess(_processHandle);
    if( suspended == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    // Take a snapshot of all running threads  
    hThreadSnap = ::CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
    if( hThreadSnap == INVALID_HANDLE_VALUE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    te32.dwSize = sizeof(THREADENTRY32);
    if( ::Thread32First(hThreadSnap, &te32) == FALSE ) 
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    // suspend all process' threads
    do 
    { 
        if( te32.th32OwnerProcessID == pid )
        {
            HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
            if( hThread == NULL )
            {
                error = LIBINJECT_ERROR;
                goto exit_label;
            }
            threads.push_back(hThread);
            ::SuspendThread(hThread);
        }
    } while( Thread32Next(hThreadSnap, &te32) );

    ::CloseHandle(hThreadSnap);
    hThreadSnap = INVALID_HANDLE_VALUE;

    ::DebugActiveProcessStop(pid);
    attached = FALSE;

    if( threads.empty() != false )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    DWORD endInstructionOffset = 0;
    if( createInjectionBuffer(libToInjectFullpath, &injectionBuffer, &endInstructionOffset) == false )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    codecaveAddress = ::VirtualAllocEx(_processHandle, 0, injectionBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if( codecaveAddress == NULL )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

	DWORD oldProtect = 0;	
	::VirtualProtectEx(_processHandle, codecaveAddress, injectionBuffer.size(), PAGE_EXECUTE_READWRITE, &oldProtect);

    SIZE_T bytesWritten = 0;
    bool codeInjected = (::WriteProcessMemory(_processHandle, codecaveAddress, &(injectionBuffer[0]), injectionBuffer.size(), &bytesWritten) != FALSE);

	::VirtualProtectEx(_processHandle, codecaveAddress, injectionBuffer.size(), oldProtect, &oldProtect);

	codeInjected = codeInjected && (::FlushInstructionCache(_processHandle, codecaveAddress, injectionBuffer.size()) != FALSE);

    if( codeInjected == false )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    codecaveExecAddress = reinterpret_cast<unsigned char*>(codecaveAddress) + 4;
    HANDLE hThread = threads[0];
    if( ::GetThreadContext(hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    
    DWORD originalEntryPoint = threadContext.Eip;
    threadContext.Eip = (DWORD)codecaveExecAddress;
    if( ::SetThreadContext(hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    if( ::ResumeThread(hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    do
    {
        if( ::SuspendThread(hThread) == (DWORD)-1 )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
        if( ::GetThreadContext(hThread, &currentContext) == FALSE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
        if( ::ResumeThread(hThread) == (DWORD)-1 )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
    }while( currentContext.Eip != (endInstructionOffset + (DWORD)codecaveAddress) );

    if( ::SuspendThread(hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    threadContext.Eip = originalEntryPoint;
    if( ::SetThreadContext(hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    //if( ::ResumeThread(hThread) == (DWORD)-1 )
    //{
    //    error = LIBINJECT_ERROR;
    //    goto exit_label;
    //}

    /*
	HANDLE hThread = ::CreateRemoteThread(_processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)(codecaveExecAddress), 0, 0, NULL);
    if( hThread == NULL )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
	::WaitForSingleObject(hThread, INFINITE); 
	DWORD threadExitCode = 1;
	::GetExitCodeThread(hThread, &threadExitCode);
    ::CloseHandle(hThread);
    if( threadExitCode != 0 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    */


exit_label:
    if( codecaveAddress != NULL )
    {
        ::VirtualFreeEx(_processHandle, codecaveAddress, 0, MEM_RELEASE);
    }

    if( attached != FALSE )
    {
        ::DebugActiveProcessStop(pid);
    }

    for( std::vector<HANDLE>::reverse_iterator it = threads.rbegin(), it_end = threads.rend(); it != it_end; ++it )
    {
        ::ResumeThread(*it);
        ::CloseHandle(*it);
    }

    return error;
}

int LIBINJECT_StartInjected( const char* _commandlineUtf8, const char* _workingDirectoryUtf8, const char* _libToInjectUtf8, LIBINJECT_PROCESS* _processHandle )
{
    if( _commandlineUtf8 == NULL )
    {
        return LIBINJECT_INVALID_PARAM;
    }

    std::vector<wchar_t> commandline;
    if( utf8_to_ucs2(_commandlineUtf8, &commandline) == false )
    {
        return LIBINJECT_INVALID_PARAM;
    }

    std::vector<wchar_t> workingDirectory;
    const wchar_t* workingDirectoryPtr = NULL;
    if( _workingDirectoryUtf8 != NULL )
    {
        if( utf8_to_ucs2(_workingDirectoryUtf8, &workingDirectory) == false )
        {
            return LIBINJECT_INVALID_PARAM;
        }
        workingDirectoryPtr = &(workingDirectory[0]);
    }

    if( _libToInjectUtf8 == NULL )
    {
        return LIBINJECT_INVALID_PARAM;
    }

    std::vector<wchar_t> libToInject;
    if( utf8_to_ucs2(_libToInjectUtf8, &libToInject) == false )
    {
        return LIBINJECT_INVALID_PARAM;
    }

    DWORD fullnameLength = ::GetFullPathNameW(&(libToInject[0]), 0, NULL, NULL);
    if( fullnameLength == 0 )
    {
        return LIBINJECT_INVALID_PARAM;
    }
    std::vector<wchar_t> libToInjectFullpath(fullnameLength);
    ::GetFullPathNameW(&(libToInject[0]), libToInjectFullpath.size(), &(libToInjectFullpath[0]), NULL);

    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)::GetProcAddress(::GetModuleHandleW(L"kernel32"), "IsWow64Process");


    int error = LIBINJECT_OK;
    STARTUPINFOW startupInfo;
    std::memset(&startupInfo, 0, sizeof(STARTUPINFOW));
    startupInfo.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION processInfo;
    std::memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    if( ::CreateProcessW(NULL, &(commandline[0]), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, workingDirectoryPtr, &startupInfo, &processInfo) == FALSE )
    {
        return LIBINJECT_ERROR;
    }

    CONTEXT threadContext = { CONTEXT_FULL, 0 };
    if( ::GetThreadContext(processInfo.hThread, &threadContext) == FALSE )
    {
        return LIBINJECT_ERROR;
    }

    std::vector<unsigned char> injectionBuffer;
    void* codecaveAddress = NULL;
    void* codecaveExecAddress = NULL;

    DWORD endInstructionOffset = 0;
    if( createInjectionBuffer(libToInjectFullpath, &injectionBuffer, &endInstructionOffset) == false )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    codecaveAddress = ::VirtualAllocEx(processInfo.hProcess, 0, injectionBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if( codecaveAddress == NULL )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

	DWORD oldProtect = 0;	
	::VirtualProtectEx(processInfo.hProcess, codecaveAddress, injectionBuffer.size(), PAGE_EXECUTE_READWRITE, &oldProtect);

    SIZE_T bytesWritten = 0;
    bool codeInjected = (::WriteProcessMemory(processInfo.hProcess, codecaveAddress, &(injectionBuffer[0]), injectionBuffer.size(), &bytesWritten) != FALSE);

	::VirtualProtectEx(processInfo.hProcess, codecaveAddress, injectionBuffer.size(), oldProtect, &oldProtect);

	codeInjected = codeInjected && (::FlushInstructionCache(processInfo.hProcess, codecaveAddress, injectionBuffer.size()) != FALSE);

    if( codeInjected == false )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    codecaveExecAddress = reinterpret_cast<unsigned char*>(codecaveAddress) + 4;

    DWORD originalEntryPoint = threadContext.Eax;
    threadContext.Eax = (DWORD)codecaveExecAddress;
    if( ::SetThreadContext(processInfo.hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    if( ::ResumeThread(processInfo.hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    do
    {
        if( ::GetThreadContext(processInfo.hThread, &threadContext) == FALSE 
			&& GetLastError() != ERROR_GEN_FAILURE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
    }while( threadContext.Eip != (endInstructionOffset + (DWORD)codecaveAddress) );

    if( ::SuspendThread(processInfo.hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    threadContext.Eip = originalEntryPoint;
    if( ::SetThreadContext(processInfo.hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    if( ::ResumeThread(processInfo.hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

exit_label:
    if( codecaveAddress != NULL )
    {
        ::VirtualFreeEx(processInfo.hProcess, codecaveAddress, 0, MEM_RELEASE);
    }

    if( processInfo.hThread != NULL )
    {
        ::CloseHandle(processInfo.hThread);
    }

    if( error != LIBINJECT_OK && processInfo.hProcess != NULL )
    {
        ::TerminateProcess(processInfo.hProcess, 0);
        ::CloseHandle(processInfo.hProcess);
    }
    else if( error == LIBINJECT_OK )
    {
        if( _processHandle != NULL )
        {
            *_processHandle = processInfo.hProcess;
        }
        else
        {
            ::CloseHandle(processInfo.hProcess);
        }
    }
    
    return error;
}
