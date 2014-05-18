cmake_minimum_required(VERSION 2.4)
project(libinject)

option(LIBINJECT_SHARED "build dll/so" OFF)
option(LIBINJECT_BUILD_SAMPLES "build samples" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(libinject_src
include/libinject/libinject.h
)

if( WIN32 )
  set(libinject_src ${libinject_src} 
  src/winimpl.cpp
  src/winx86buffer.h
  )
endif()

set( LIBINJECT_LIB_MODE )
if( LIBINJECT_SHARED )
    add_definitions(-DLIBINJECT_SHARED_BUILD)
    set( LIBINJECT_LIB_MODE SHARED )
endif()

include_directories(include)
add_library(libinject ${LIBINJECT_LIB_MODE} ${libinject_src})
set_target_properties(libinject PROPERTIES PREFIX "")

if( LIBINJECT_BUILD_SAMPLES )
  add_subdirectory(samples)
endif()