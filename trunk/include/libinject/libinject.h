#ifndef _LIBINJECT_H_
#define _LIBINJECT_H_

#ifdef __cplusplus
extern "C" {
#endif 


#ifdef _WIN32

typedef unsigned long LIBINJECT_PID;
typedef unsigned long LIBINJECT_TID;

#else
#   error "Unknown platform"
#endif

#ifdef LIBINJECT_SHARED
#   ifdef _WIN32
#       ifdef LIBINJECT_SHARED_BUILD
#           define LBINJECT_EXPORT __declspec(dllexport)
#       else
#           define LIBNJECT_EXPORT __declspec(dllimport)
#       endif
#   endif
#endif

#ifndef LIBINJECT_EXPORT
#   define LIBINJECT_EXPORT
#endif
    
#define LIBINJECT_OK                0
#define LIBINJECT_INVALID_PARAM     1
#define LIBINJECT_ERROR             2
//#define 

extern LIBINJECT_EXPORT int LIBINJECT_Inject( LIBINJECT_PID _processId, const char* _libToInjectUtf8 );

extern LIBINJECT_EXPORT int LIBINJECT_StartInjected( const char* _commandlineUtf8, const char* _workingDirectoryUtf8, const char* _libToInjectUtf8, LIBINJECT_PID* _processId, LIBINJECT_TID* _threadId );


#ifdef __cplusplus
}   // extern "C"
#endif

#endif  _LIBINJECT_H_
