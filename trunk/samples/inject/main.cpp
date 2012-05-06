
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

int main( int _argc, char* _argv[] )
{
    if( _argc > 1 )
    {
        if( std::strcmp(_argv[1], "-pid") == 0 )
        {
            long pid = std::atol(_argv[2]);
            LIBINJECT_PROCESS hProcess = PidToHandle(pid);
            for( int i = 0; i < (_argc - 3); ++i )
            {
                LIBINJECT_Inject(hProcess, _argv[i + 3]);
            }
        }
        else
        {
            std::vector<const char*> libsToInject(_argc);
            for( int i = 0; i < (_argc - 1); ++i )
            {
                libsToInject[i] = _argv[i + 2];
            }
            int result = LIBINJECT_StartInjected(_argv[1], NULL, &(libsToInject[0]), NULL);
            return (result == LIBINJECT_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }
    else
    {
        std::printf("inject <commandline> [libToInject ...]\n"
                    "inject -pid <pid> [libToInject ...]\n");
    }
    return EXIT_SUCCESS;
}
