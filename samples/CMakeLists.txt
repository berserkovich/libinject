cmake_minimum_required(VERSION 2.4)

add_executable(test test/main.cpp)
target_link_libraries(test libinject)

add_library(testdll SHARED test/dllmain.cpp)
