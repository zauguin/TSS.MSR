cmake_minimum_required(VERSION 3.24)
project(TSS.CPP CXX)

find_package(cryptopp REQUIRED)

aux_source_directory(Src source_files)
aux_source_directory(Samples sample_files)

list(APPEND LIB_MODES SHARED STATIC)
list(APPEND LIB_TARGETS TSS.CPP TSS.CPP_static)

foreach(target mode IN ZIP_LISTS LIB_TARGETS LIB_MODES)
  add_library(${target} ${mode} ${source_files})

  target_link_libraries(${target} cryptopp::cryptopp)

  set_property(TARGET ${target} PROPERTY CXX_STANDARD 11)
  set_property(TARGET ${target} PROPERTY CXX_STANDARD_REQUIRED ON)

  target_compile_definitions(${target} PUBLIC
    "$<$<CONFIG:Debug>:DEBUG;_DEBUG>"
  )
  target_compile_definitions(${target} PRIVATE _TPMCPPLIB)
  target_include_directories(${target} PUBLIC include)

  target_compile_definitions(${target} PRIVATE NO_SM3)
endforeach()

add_executable(Samples ${sample_files})
target_link_libraries(Samples TSS.CPP_static)

install(TARGETS ${LIB_TARGETS})
install(DIRECTORY "include/" # source directory
        DESTINATION "include/TSS.CPP" # target directory
        FILES_MATCHING # install only matched files
        PATTERN "*.h" # select header files
)
