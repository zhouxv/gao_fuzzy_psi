cmake_minimum_required(VERSION 3.22)
project(FPSI)

include_directories(frontend)
include_directories(fuzzy_mapping)
include_directories(Goldwasser-Micali)
include_directories(RBOKVS)
include_directories(FPSI-for-Hamming)
include_directories(BLAKE3)

file(GLOB_RECURSE SRCS
    frontend/*.cpp
    fuzzy_mapping/*.cpp
    Goldwasser-Micali/*.cpp
    RBOKVS/*.cpp
    FPSI-for-Hamming/*.cpp
)

add_executable(main ${SRCS})

target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2)

set(CMAKE_BUILD_TYPE Release)

# ############################################
# Link  libOTe                   #
# ############################################
find_package(libOTe REQUIRED HINTS "./libOTe")

target_link_libraries(main oc::libOTe)

# ############################################
# Link  Myblake3                 #
# ############################################
target_link_libraries(main ${CMAKE_SOURCE_DIR}/BLAKE3/libblake3.so)

# ############################################
# Link  IPCL                     #
# ############################################
set(IPCL_DIR "./install/lib/cmake/ipcl-2.0.0/")

find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main IPCL::ipcl)

# ############################################
# Link  GMP                      #
# ############################################
target_link_libraries(main /lib/x86_64-linux-gnu/libgmpxx.a /lib/x86_64-linux-gnu/libgmp.a)
