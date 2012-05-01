cmake_minimum_required(VERSION 2.4)
project(libinject)

option(LIBINJECT_BUILD_SAMPLES "build samples" ON)

set(libinject_src
include/libinject/libinject.h
)

if( WIN32 )
  set(libinject_src ${libinject_src} 
  src/winimpl.cpp
  src/winx86buffer.h
  )
endif()

include_directories(include)
add_library(libinject ${libinject_src})
set_target_properties(libinject PROPERTIES PREFIX "")

if( LIBINJECT_BUILD_SAMPLES )
  add_subdirectory(samples)
endif()