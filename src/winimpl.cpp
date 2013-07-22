#include "libinject/libinject.h"

#include "winx86buffer.h"

#include <algorithm> 
#include <cassert>
#include <cstring>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

namespace 
{
    struct InjectionBufferInfo
    {
        unsigned char* codeBlock;
        unsigned char* codeBlockEndTrapInstructionAddress;
	    unsigned char* dataBlock;
	    unsigned char* dataBlockStackAddress;
    };

    bool utf8_to_ucs2( const char* _utf8string, std::vector<wchar_t>* _ucs2string )
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

    void releaseInjectionBuffer( HANDLE _hProcess, const InjectionBufferInfo& _bufferInfo )
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

    int createInjectionBuffer( HANDLE _hProcess, const std::vector<wchar_t>& _libToInject, InjectionBufferInfo* _injectionBufferInfo )
    {
        assert(_libToInject.empty() == false);
        assert(_injectionBufferInfo);

        size_t dataSize = sizeof(x86TemplateBufferData) + _libToInject.size() * sizeof(wchar_t);
        size_t stackSize = 100 * 1024;  // 100K

        InjectionBufferInfo bufferInfo = {};

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

	    bufferInfo.codeBlockEndTrapInstructionAddress = bufferInfo.codeBlock + sizeof(x86TemplateBuffer) - 2;
	    bufferInfo.dataBlockStackAddress = bufferInfo.dataBlock + stackSize;
        *_injectionBufferInfo = bufferInfo;
        return LIBINJECT_OK;
    }

    int SuspendProcess( HANDLE _hProcess, DWORD _threadsDesiredAccess, std::vector<HANDLE>* _threads )
    {
        assert(_threads);

        int error = LIBINJECT_OK;
        HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
        THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
        FILETIME minThreadCreationTime = { 0xFFFFFFFF, 0xFFFFFFFF };
        FILETIME threadCreationTime, threadExitTime, threadKernelTime, threadUserTime;
        DWORD processId = ::GetProcessId(_hProcess);
        size_t threadsCount = 0;
        bool attached = ::DebugActiveProcess(processId) != FALSE;
        if( !attached )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }

        if( ::DebugBreakProcess(_hProcess) == FALSE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }

        hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
        if( hThreadSnap == INVALID_HANDLE_VALUE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }

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
                HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | _threadsDesiredAccess, FALSE, te32.th32ThreadID);
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

                _threads->push_back(hThread);
                threadsCount += 1;

                threadCreationTime.dwHighDateTime = 0xFFFFFFFF;
                threadCreationTime.dwHighDateTime = 0xFFFFFFFF;
                ::GetThreadTimes(hThread, &threadCreationTime, &threadExitTime, &threadKernelTime, &threadUserTime);
                if( ::CompareFileTime(&minThreadCreationTime, &threadCreationTime) == 1 )
                {
                    minThreadCreationTime = threadCreationTime;
                    std::swap((*_threads)[0], _threads->back());
                }
            }
        } while( Thread32Next(hThreadSnap, &te32) );

        if( threadsCount == 0 )
        {
            error = LIBINJECT_ERROR;
        }

    exit_label:
        if( hThreadSnap != INVALID_HANDLE_VALUE )
        {
            ::CloseHandle(hThreadSnap);
        }

        if( attached )
        {
            ::DebugActiveProcessStop(processId);
        }

        return error;
    }

    int InjectThread( HANDLE _hProcess, HANDLE _hThread, const std::vector<wchar_t>& _libToInjectFullpath )
    {
        int error = LIBINJECT_OK;
        InjectionBufferInfo injectionBuffer = {};
        CONTEXT originalContext = { CONTEXT_FULL, 0 };
        CONTEXT threadContext = { CONTEXT_CONTROL, 0 };
        bool suspended = true;

        error = createInjectionBuffer(_hProcess, _libToInjectFullpath, &injectionBuffer);
        if( error != LIBINJECT_OK )
        {
            goto exit_label;
        }

        if( ::GetThreadContext(_hThread, &originalContext) == FALSE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
    
        threadContext = originalContext;
        threadContext.Eip = (DWORD)injectionBuffer.codeBlock;
	    threadContext.Esp = (DWORD)injectionBuffer.dataBlockStackAddress;
	    threadContext.Ebp = (DWORD)injectionBuffer.dataBlockStackAddress;

        if( ::SetThreadContext(_hThread, &threadContext) == FALSE )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }

        if( ::ResumeThread(_hThread) == (DWORD)-1 )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
        suspended = false;

        do
        {
		    ::Sleep(0);
            if( ::GetThreadContext(_hThread, &threadContext) == FALSE 
			    && GetLastError() != ERROR_GEN_FAILURE )
            {
                error = LIBINJECT_ERROR;
                goto exit_label;
            }
	    }while( threadContext.Eip != ((DWORD)injectionBuffer.codeBlockEndTrapInstructionAddress) );

        if( ::SuspendThread(_hThread) == (DWORD)-1 )
        {
            error = LIBINJECT_ERROR;
            goto exit_label;
        }
        suspended = true;

        if( ::GetThreadContext(_hThread, &threadContext) == FALSE )
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

	    if( lastError != ERROR_SUCCESS )
	    {
		    error = LIBINJECT_ERROR;
	    }

    exit_label:
        if( !suspended )
        {
            ::SuspendThread(_hThread);
        }

        releaseInjectionBuffer(_hProcess, injectionBuffer);

        if( ::SetThreadContext(_hThread, &originalContext) == FALSE )
        {
            error = LIBINJECT_ERROR;
        }

        return error;
    }

    int InjectProcess( HANDLE _hProcess, const std::vector<wchar_t>& _libToInjectFullpath )
    {
        std::vector<HANDLE> threads;

        int error = SuspendProcess(_hProcess, THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, &threads);
        if( error == LIBINJECT_OK )
        {
            assert(!threads.empty());
            error = InjectThread(_hProcess, threads[0], _libToInjectFullpath);
        }

        for( std::vector<HANDLE>::iterator it = threads.begin(), it_end = threads.end(); it != it_end; ++it )
        {
            ::ResumeThread(*it);
            ::CloseHandle(*it);
        }

        return error;
    }
}   // namespace

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

	int error = InjectProcess(hProcess, libToInjectFullpath);

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

	int error = InjectThread(processInfo.hProcess, processInfo.hThread, libToInjectFullpath);

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
