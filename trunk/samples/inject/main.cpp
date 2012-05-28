
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "libinject/libinject.h"

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
    if( _argc > 2 )
    {
        if( std::strcmp(_argv[1], "-pid") == 0 )
        {
            LIBINJECT_PID pid = static_cast<LIBINJECT_PID>(std::atol(_argv[2]));
            int result = LIBINJECT_Inject(pid, _argv[3]);
            return check_result(result) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
        else
        {
            int result = LIBINJECT_StartInjected(_argv[2], NULL, _argv[1], NULL, NULL);
            return check_result(result) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }
    else
    {
        std::printf("inject <libToInject> <commandline>\n"
                    "inject -pid <pid> <libToInject>\n");
    }
    return EXIT_SUCCESS;
}
