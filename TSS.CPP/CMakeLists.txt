cmake_minimum_required(VERSION 3.24)
project(TSS.CPP CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
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
  target_include_directories(${target} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include/TSS.CPP>)

  target_compile_definitions(${target} PRIVATE NO_SM3)
endforeach()

add_executable(Samples ${sample_files})
target_link_libraries(Samples TSS.CPP_static)

install(TARGETS ${LIB_TARGETS} EXPORT TSS.CPP FILE_SET HEADERS)
install(DIRECTORY "include/"
        DESTINATION "include/TSS.CPP"
        FILES_MATCHING
        PATTERN "*.h"
)
install(EXPORT TSS.CPP
        FILE TSS.CPPTargets.cmake
        NAMESPACE TSS.CPP::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TSS.CPP
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/TSS.CPPConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TSS.CPP
)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/TSS.CPPConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/TSS.CPPConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TSS.CPP
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/TSS.CPPConfigVersion.cmake"
  VERSION 0.0.1-MK
  COMPATIBILITY AnyNewerVersion
)
