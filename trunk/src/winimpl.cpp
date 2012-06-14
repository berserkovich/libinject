#include "libinject/libinject.h"

#include "winx86buffer.h"

#include <algorithm> 
#include <cassert>
#include <cstring>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

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

static HANDLE IsProcessCreatedSuspended( HANDLE _hProcess )
{
	FILETIME creationTime, exitTime, kernelTime, userTime;
	if( ::GetProcessTimes(_hProcess, &creationTime, &exitTime, &kernelTime, &userTime) == FALSE )
	{
		return NULL;
	}

	if( kernelTime.dwLowDateTime != 0 || kernelTime.dwHighDateTime != 0
		|| userTime.dwLowDateTime != 0 || userTime.dwHighDateTime != 0 )
	{
		return NULL;
	}

	// ok, looks like it is created suspended. let's check if it has one and only suspended thread to be sure
    HANDLE hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
    if( hThreadSnap == INVALID_HANDLE_VALUE )
    {
        return NULL;
    }

    THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
    if( ::Thread32First(hThreadSnap, &te32) == FALSE ) 
    {
		::CloseHandle(hThreadSnap);
        return NULL;
    }

	DWORD processId = ::GetProcessId(_hProcess);
	std::vector<HANDLE> threads;
	bool somethingWrong = false;
    do 
    { 
        if( te32.th32OwnerProcessID == processId )
        {
            HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
            if( hThread == NULL )
            {
				somethingWrong = true;
				break;
            }
            threads.push_back(hThread);
        }
    } while( Thread32Next(hThreadSnap, &te32) );
	::CloseHandle(hThreadSnap);

	DWORD suspendCount = -1;
	if( threads.size() == 1 )
	{
		suspendCount = ::SuspendThread(threads[0]);
		::ResumeThread(threads[0]);
	}

	HANDLE mainThread = NULL;
	bool suspended = (suspendCount > 0) && (somethingWrong == false);
	if( suspended == false )
	{
		for( std::vector<HANDLE>::iterator it = threads.begin(), it_end = threads.end(); it != it_end; ++it )
		{
			::CloseHandle(*it);
		}
	}
	else
	{
		mainThread = threads[0];
	}

	return mainThread;
}

static int InjectProcessLive( HANDLE _hProcess, const std::vector<wchar_t>& _libToInjectFullpath )
{
    BOOL suspended = FALSE;
    BOOL attached = FALSE;
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
    THREADENTRY32 te32;
    std::vector<HANDLE> threads;
    InjectionBufferInfo injectionBuffer = { NULL };
    CONTEXT threadContext = { CONTEXT_CONTROL, 0 };
    CONTEXT currentContext = { CONTEXT_CONTROL, 0 };
	DWORD processId = ::GetProcessId(_hProcess);
	int error = LIBINJECT_OK;

    attached = ::DebugActiveProcess(processId);
    if( attached == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    // break all the process threads
    suspended = ::DebugBreakProcess(_hProcess);
    if( suspended == FALSE )
    {
        error = LIBINJECT_ERROR;
        goto exit_label;
    }

    // Take a snapshot of all running threads  
    hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
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
        if( te32.th32OwnerProcessID == processId )
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

    if( ::DebugActiveProcessStop(processId) == FALSE )
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

    error = createInjectionBuffer(_hProcess, _libToInjectFullpath, &injectionBuffer);
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
		::Sleep(0);
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

	DWORD lastError = 0;
	DWORD bytesRead = 0;
	if( ::ReadProcessMemory(_hProcess, injectionBuffer.dataBlock, &lastError, sizeof(DWORD), &bytesRead) == FALSE
		|| bytesRead != sizeof(DWORD) )
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

	if( lastError != ERROR_SUCCESS )
	{
		error = LIBINJECT_ERROR;
	}
exit_label:
    releaseInjectionBuffer(_hProcess, injectionBuffer);

    if( attached != FALSE )
    {
        ::DebugActiveProcessStop(processId);
    }

    for( std::vector<HANDLE>::reverse_iterator it = threads.rbegin(), it_end = threads.rend(); it != it_end; ++it )
    {
        ::ResumeThread(*it);
        ::CloseHandle(*it);
    }

    return error;
}

static int InjectProcessCreatedSuspended( HANDLE _hProcess, HANDLE _hMainThread, const std::vector<wchar_t>& _libToInjectFullpath )
{
	CONTEXT threadContext = { CONTEXT_CONTROL | CONTEXT_INTEGER, 0 };
    if( ::GetThreadContext(_hMainThread, &threadContext) == FALSE )
    {
        return LIBINJECT_ERROR;
    }

    InjectionBufferInfo injectionBuffer = { NULL };
    if( createInjectionBuffer(_hProcess, _libToInjectFullpath, &injectionBuffer) != LIBINJECT_OK )
    {
        return LIBINJECT_ERROR;
    }

    DWORD originalEntryPoint = threadContext.Eax;
    threadContext.Eax = (DWORD)injectionBuffer.codeBlock;
    if( ::SetThreadContext(_hMainThread, &threadContext) == FALSE )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }

    if( ::ResumeThread(_hMainThread) == (DWORD)-1 )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }

    do
    {
		::Sleep(0);
        if( ::GetThreadContext(_hMainThread, &threadContext) == FALSE 
			&& GetLastError() != ERROR_GEN_FAILURE )
        {
	        releaseInjectionBuffer(_hProcess, injectionBuffer);
			return LIBINJECT_ERROR;
        }
	}while( threadContext.Eip != ((DWORD)injectionBuffer.codeBlockBeginTrapInstructionAddress) );

    if( ::SuspendThread(_hMainThread) == (DWORD)-1 )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }

	DWORD originalEsp = threadContext.Esp;
	DWORD originalEbp = threadContext.Ebp;
	threadContext.Eip = (DWORD)injectionBuffer.codeBlockTrapBodyInstructionAddress;
	threadContext.Ebp = (DWORD)injectionBuffer.dataBlockStackAddress;
	threadContext.Esp = (DWORD)injectionBuffer.dataBlockStackAddress;

    if( ::SetThreadContext(_hMainThread, &threadContext) == FALSE )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }
    if( ::ResumeThread(_hMainThread) == (DWORD)-1 )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }

    do
    {
		::Sleep(0);
        if( ::GetThreadContext(_hMainThread, &threadContext) == FALSE 
			&& GetLastError() != ERROR_GEN_FAILURE )
        {
	        releaseInjectionBuffer(_hProcess, injectionBuffer);
			return LIBINJECT_ERROR;
        }
	}while( threadContext.Eip != ((DWORD)injectionBuffer.codeBlockEndTrapInstructionAddress) );

    if( ::SuspendThread(_hMainThread) == (DWORD)-1 )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }

	DWORD lastError = 0;
	DWORD bytesRead = 0;
	if( ::ReadProcessMemory(_hProcess, injectionBuffer.dataBlock, &lastError, sizeof(DWORD), &bytesRead) == FALSE
		|| bytesRead != sizeof(DWORD) )
	{
		releaseInjectionBuffer(_hProcess, injectionBuffer);
		return LIBINJECT_ERROR;
	}
    threadContext.Eip = originalEntryPoint;
    threadContext.Esp = originalEsp;
	threadContext.Ebp = originalEbp;
    if( ::SetThreadContext(_hMainThread, &threadContext) == FALSE )
    {
        releaseInjectionBuffer(_hProcess, injectionBuffer);
        return LIBINJECT_ERROR;
    }

    releaseInjectionBuffer(_hProcess, injectionBuffer);
	return (lastError == 0) ? LIBINJECT_OK : LIBINJECT_ERROR;
}

int LIBINJECT_Inject( LIBINJECT_PID _processId, const char* _libToInjectUtf8 )
{
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

	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, _processId);
	if( hProcess == NULL )
	{
		return LIBINJECT_INVALID_PARAM;
	}

	int error = LIBINJECT_OK;
	HANDLE hMainThread = IsProcessCreatedSuspended(hProcess);
	if( hMainThread != NULL )
	{
		error = InjectProcessCreatedSuspended(hProcess, hMainThread, libToInjectFullpath);
		::CloseHandle(hMainThread);
	}
	else
	{
		error = InjectProcessLive(hProcess, libToInjectFullpath);
	}

	::CloseHandle(hProcess);
	return error;
}

int LIBINJECT_StartInjected( const char* _commandlineUtf8, const char* _workingDirectoryUtf8, const char* _libToInjectUtf8, LIBINJECT_PID* _processId, LIBINJECT_TID* _threadId )
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

    STARTUPINFOW startupInfo;
    std::memset(&startupInfo, 0, sizeof(STARTUPINFOW));
    startupInfo.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION processInfo;
    std::memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
    if( ::CreateProcessW(NULL, &(commandline[0]), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, workingDirectoryPtr, &startupInfo, &processInfo) == FALSE )
    {
        return LIBINJECT_ERROR;
    }

	int error = InjectProcessCreatedSuspended(processInfo.hProcess, processInfo.hThread, libToInjectFullpath);

	if( ::ResumeThread(processInfo.hThread) == (DWORD)-1 )
	{
		error = LIBINJECT_ERROR;
	}

	if( error == LIBINJECT_OK )
	{
		if( _processId != NULL )
		{
			*_processId = processInfo.dwProcessId;
		}

		if( _threadId != NULL )
		{
			*_threadId = processInfo.dwThreadId;
		}
	}
	else
	{
        ::TerminateProcess(processInfo.hProcess, 0);
	}

    ::CloseHandle(processInfo.hThread);
    ::CloseHandle(processInfo.hProcess);
    return error;
}
