cmake_minimum_required(VERSION 2.4)

add_library(NVPerfHUDForceEnable SHARED dllmain.cpp)
target_link_libraries(NVPerfHUDForceEnable minhook libinject)
