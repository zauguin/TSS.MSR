cmake_minimum_required(VERSION 3.24)
project(TSS.CPP CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

aux_source_directory(Src source_files)
aux_source_directory(Samples sample_files)

add_library(TSS_static STATIC ${source_files})
add_library(TSS_shared SHARED ${source_files})

target_link_libraries(TSS_static OpenSSL::Crypto)
target_link_libraries(TSS_shared OpenSSL::Crypto)

set_property(TARGET TSS_static PROPERTY CXX_STANDARD 11)
set_property(TARGET TSS_static PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET TSS_shared PROPERTY CXX_STANDARD 11)
set_property(TARGET TSS_shared PROPERTY CXX_STANDARD_REQUIRED ON)

target_compile_definitions(TSS_static PUBLIC
  "$<$<CONFIG:Debug>:DEBUG;_DEBUG>"
)
target_compile_definitions(TSS_static PRIVATE _TPMCPPLIB)
target_include_directories(TSS_static PUBLIC include)

target_compile_definitions(TSS_shared PUBLIC
  "$<$<CONFIG:Debug>:DEBUG;_DEBUG>"
)
target_compile_definitions(TSS_shared PRIVATE _TPMCPPLIB)
target_include_directories(TSS_shared PUBLIC include)

find_file(openssl_sm3 NAMES openssl/sm3.h)
if(openssl_sm3 STREQUAL "openssl_sm3-NOTFOUND")
  target_compile_definitions(TSS_static PRIVATE OPENSSL_NO_SM3)
  target_compile_definitions(TSS_shared PRIVATE OPENSSL_NO_SM3)
endif()

add_executable(Samples ${sample_files})
target_link_libraries(Samples TSS_static)
