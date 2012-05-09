
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "libinject/libinject.h"

#ifdef _WIN32
    LIBINJECT_PROCESS PidToHandle( long _pid )
    {
        return ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, _pid);
    }
#endif

bool check_result( int _result )
{
    if( _result == LIBINJECT_INVALID_PARAM )
    {
        std::printf("Injection failed: invalid parameters\n");
        return false;
    }
    else if( _result == LIBINJECT_ERROR )
    {
        std::printf("Injection failed: injection error\n");
        return false;
    }
    else if( _result == LIBINJECT_OK )
    {
        std::printf("Injection succeeded\n");
        return true;
    }
    return true;
 }

int main( int _argc, char* _argv[] )
{
    //__asm
    //{
    //    pushad
    //    popad
    //}
    if( _argc > 2 )
    {
        if( std::strcmp(_argv[1], "-pid") == 0 )
        {
            long pid = std::atol(_argv[2]);
            LIBINJECT_PROCESS hProcess = PidToHandle(pid);
            int result = LIBINJECT_Inject(hProcess, _argv[3]);
            return check_result(result) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else
        {
            int result = LIBINJECT_StartInjected(_argv[1], NULL, _argv[2], NULL);
            return check_result(result) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }
    else
    {
        std::printf("inject <commandline> <libToInject>\n"
                    "inject -pid <pid> <libToInject>\n");
    }
    return EXIT_SUCCESS;
}
