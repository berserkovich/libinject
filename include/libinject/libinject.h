#ifndef _LIBINJECT_H_
#define _LIBINJECT_H_

#ifdef __cplusplus
extern "C" {
#endif 


#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
typedef HANDLE LIBINJECT_PROCESS;

#else
#error "Unknown platform"
#endif

#define LIBINJECT_OK                0
#define LIBINJECT_INVALID_PARAM     1
#define LIBINJECT_ERROR             2
//#define 

int LIBINJECT_Inject( LIBINJECT_PROCESS _processHandle, const char* _libToInjectUtf8 );

int LIBINJECT_StartInjected( const char* _commandlineUtf8, const char* _workingDirectoryUtf8, const char* const* _libsToInjectUtf8, LIBINJECT_PROCESS* _processHandle );


#ifdef __cplusplus
}   // extern "C"
#endif

#endif  _LIBINJECT_H_
