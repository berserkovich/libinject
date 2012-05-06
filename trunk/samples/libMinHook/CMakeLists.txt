cmake_minimum_required(VERSION 2.4)

set( MINHOOK_SRC
src/hook.cpp
src/buffer.cpp
src/trampoline.cpp
src/trampoline.h
src/export.cpp
src/hook.h
src/thread.cpp
src/buffer.h
src/thread.h
src/pstdint.h

src/HDE32/hde32.h
src/HDE32/hde32.c
src/HDE32/table32.h

src/HDE64/include/hde64.h
src/HDE64/src/hde64.c
src/HDE64/src/table64.h
)

add_library(minhook ${MINHOOK_SRC})
