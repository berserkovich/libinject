#include "libinject/libinject.h"

#include "winx86buffer.h"

#include <TlHelp32.h>

#include <algorithm> 
#include <cassert>
#include <cstring>
#include <vector>

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

struct InjectionBufferInfo
{
    unsigned char* codeBlock;
	unsigned char* codeBlockBeginTrapInstructionAddress;
	unsigned char* codeBlockTrapBodyInstructionAddress;
    unsigned char* codeBlockEndTrapInstructionAddress;
	unsigned char* dataBlock;
	unsigned char* dataBlockStackAddress;
};

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

static void releaseInjectionBuffer( HANDLE _hProcess, const InjectionBufferInfo& _bufferInfo )
{
	if( _bufferInfo.dataBlock != NULL )
	{
		::VirtualFreeEx(_hProcess, _bufferInfo.dataBlock, 0, MEM_RELEASE);
	}

    if( _bufferInfo.codeBlock != NULL )
    {
        ::VirtualFreeEx(_hProcess, _bufferInfo.codeBlock, 0, MEM_RELEASE);
    }
}

static int createInjectionBuffer( HANDLE _hProcess, const std::vector<wchar_t>& _libToInject, InjectionBufferInfo* _injectionBufferInfo )
{
    assert(_libToInject.empty() == false);
    assert(_injectionBufferInfo);

    size_t dataSize = sizeof(x86TemplateBufferData) + _libToInject.size() * sizeof(wchar_t);
    size_t stackSize = 100 * 1024;  // 100K

    InjectionBufferInfo bufferInfo = { NULL };

    // allocate code buffer
	bufferInfo.codeBlock = static_cast<unsigned char*>(::VirtualAllocEx(_hProcess, 0, sizeof(x86TemplateBuffer), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if( bufferInfo.codeBlock == NULL )
    {
        return LIBINJECT_ERROR;
    }

    // copy code template into buffer
    SIZE_T bytesWritten = 0;
    if( ::WriteProcessMemory(_hProcess, bufferInfo.codeBlock, &(x86TemplateBuffer[0]), sizeof(x86TemplateBuffer), &bytesWritten) == FALSE 
        || bytesWritten != sizeof(x86TemplateBuffer) )
    {
        releaseInjectionBuffer(_hProcess, bufferInfo);
        return LIBINJECT_ERROR;
    }

	bufferInfo.dataBlock = static_cast<unsigned char*>(::VirtualAllocEx(_hProcess, 0, stackSize + dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if( bufferInfo.dataBlock == NULL )
	{
		releaseInjectionBuffer(_hProcess, bufferInfo);
		return LIBINJECT_ERROR;
	}

	unsigned char* dataAddress = bufferInfo.dataBlock + stackSize;
    if( ::WriteProcessMemory(_hProcess, dataAddress, &(x86TemplateBufferData[0]), sizeof(x86TemplateBufferData), &bytesWritten) == FALSE 
        || bytesWritten != sizeof(x86TemplateBufferData) )
    {
        releaseInjectionBuffer(_hProcess, bufferInfo);
        return LIBINJECT_ERROR;
    }
    dataAddress += bytesWritten;

    if( ::WriteProcessMemory(_hProcess, dataAddress, reinterpret_cast<const unsigned char*>(&(_libToInject[0])), _libToInject.size() * sizeof(wchar_t), &bytesWritten) == FALSE 
        || bytesWritten != (_libToInject.size() * sizeof(wchar_t)) )
    {
        releaseInjectionBuffer(_hProcess, bufferInfo);
        return LIBINJECT_ERROR;
    }

	// set code block protection to execute-readonly
    DWORD oldProtection = 0;
    if( ::VirtualProtectEx(_hProcess, bufferInfo.codeBlock, sizeof(x86TemplateBuffer), PAGE_EXECUTE_READ, &oldProtection) == FALSE )
    {
        releaseInjectionBuffer(_hProcess, bufferInfo);
        return LIBINJECT_ERROR;
    }

    if( ::FlushInstructionCache(_hProcess, bufferInfo.codeBlock, sizeof(x86TemplateBuffer)) == FALSE )
    {
        releaseInjectionBuffer(_hProcess, bufferInfo);
        return LIBINJECT_ERROR;
    }

	bufferInfo.codeBlockBeginTrapInstructionAddress = bufferInfo.codeBlock;
	bufferInfo.codeBlockTrapBodyInstructionAddress = bufferInfo.codeBlock + 2;
	bufferInfo.codeBlockEndTrapInstructionAddress = bufferInfo.codeBlock + sizeof(x86TemplateBuffer) - 2;
	bufferInfo.dataBlockStackAddress = bufferInfo.dataBlock + stackSize;
    *_injectionBufferInfo = bufferInfo;
    return LIBINJECT_OK;
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
    InjectionBufferInfo injectionBuffer = { NULL };
    CONTEXT threadContext = { CONTEXT_CONTROL, 0 };
    CONTEXT currentContext = { CONTEXT_CONTROL, 0 };

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
            if( ::SuspendThread(hThread) == (DWORD)-1 )
			{
				error = LIBINJECT_ERROR;
				goto exit_label;
			}
            threads.push_back(hThread);
        }
    } while( Thread32Next(hThreadSnap, &te32) );

    ::CloseHandle(hThreadSnap);
    hThreadSnap = INVALID_HANDLE_VALUE;

    if( ::DebugActiveProcessStop(pid) == FALSE )
	{
		error = LIBINJECT_ERROR;
		goto exit_label;
	}
    attached = FALSE;

    if( threads.empty() != false )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    error = createInjectionBuffer(_processHandle, libToInjectFullpath, &injectionBuffer);
    if( error != LIBINJECT_OK )
    {
        goto exit_label;
    }

    HANDLE hThread = threads[0];
    if( ::GetThreadContext(hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
    
	DWORD originalEntryPoint = threadContext.Eip;
	DWORD originalEsp = threadContext.Esp;
	DWORD originalEbp = threadContext.Ebp;
	threadContext.Eip = (DWORD)injectionBuffer.codeBlockTrapBodyInstructionAddress;	// we can skip begin trap as stack can be set now
	threadContext.Esp = (DWORD)injectionBuffer.dataBlockStackAddress;
	threadContext.Ebp = (DWORD)injectionBuffer.dataBlockStackAddress;

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
        if( ::GetThreadContext(hThread, &currentContext) == FALSE 
			&& GetLastError() != ERROR_GEN_FAILURE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
	}while( currentContext.Eip != ((DWORD)injectionBuffer.codeBlockEndTrapInstructionAddress) );

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

    threadContext.Eip = originalEntryPoint;
	threadContext.Ebp = originalEbp;
	threadContext.Esp = originalEsp;
    if( ::SetThreadContext(hThread, &threadContext) == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }
	::ResumeThread(hThread);

exit_label:
    releaseInjectionBuffer(_processHandle, injectionBuffer);

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

    //LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)::GetProcAddress(::GetModuleHandleW(L"kernel32"), "IsWow64Process");

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

	CONTEXT threadContext = { CONTEXT_CONTROL | CONTEXT_INTEGER, 0 };
    if( ::GetThreadContext(processInfo.hThread, &threadContext) == FALSE )
    {
        return LIBINJECT_ERROR;
    }

    InjectionBufferInfo injectionBuffer = { NULL };
    error = createInjectionBuffer(processInfo.hProcess, libToInjectFullpath, &injectionBuffer);
    if( error != LIBINJECT_OK )
    {
        goto exit_label;
    }

    DWORD originalEntryPoint = threadContext.Eax;
    threadContext.Eax = (DWORD)injectionBuffer.codeBlock;
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
	}while( threadContext.Eip != ((DWORD)injectionBuffer.codeBlockBeginTrapInstructionAddress) );

    if( ::SuspendThread(processInfo.hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

	DWORD originalEsp = threadContext.Esp;
	DWORD originalEbp = threadContext.Ebp;
	threadContext.Eip = (DWORD)injectionBuffer.codeBlockTrapBodyInstructionAddress;
	threadContext.Ebp = (DWORD)injectionBuffer.dataBlockStackAddress;
	threadContext.Esp = (DWORD)injectionBuffer.dataBlockStackAddress;

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
	}while( threadContext.Eip != ((DWORD)injectionBuffer.codeBlockEndTrapInstructionAddress) );

    if( ::SuspendThread(processInfo.hThread) == (DWORD)-1 )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    threadContext.Eip = originalEntryPoint;
    threadContext.Esp = originalEsp;
	threadContext.Ebp = originalEbp;
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
    if( processInfo.hProcess != NULL )
    {
        releaseInjectionBuffer(processInfo.hProcess, injectionBuffer);
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
