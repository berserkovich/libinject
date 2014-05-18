cmake_minimum_required(VERSION 2.4)

add_executable(inject inject/main.cpp)
target_link_libraries(inject libinject)

if( WIN32 )
  add_subdirectory(libMinHook)
  include_directories(libMinHook)
endif()

add_subdirectory(NVPerfHUDForceEnable)

