# Copyright (C) 2026 Vincent Hengel.
# For licensing information see LICENSE at the root of this distribution.
#
# A CMake target beside the premake build.
#
# premake remains the build for this repository's own samples. This file exists
# so that a consumer using CMake (equilibrium, mmkit, mmgfx and anything built
# on them) can add_subdirectory() the loader the same way it adds the others,
# rather than vendoring the sources or shelling out to a second build system.
#
# Only the NT loader is offered here. The ELF loader is work in progress and
# has no consumer yet, and offering a target for it would be claiming more than
# is true.

cmake_minimum_required(VERSION 3.20)
project(loadr CXX)

if(NOT WIN32)
  message(FATAL_ERROR
    "loadr's NT loader maps PE images into the running process and is Windows "
    "only. Cross-compiling from Linux is supported, but the target has to be "
    "Windows: use a mingw toolchain file, or MSVC through a wine prefix.")
endif()

add_library(loadr_nt STATIC
  ntloader/dir_context.cc
  ntloader/loader.cc
  ntloader/module_list.cc
  ntloader/nt_file_loader.cc
  ntloader/snapshot.cc
)
add_library(loadr::nt ALIAS loadr_nt)

target_include_directories(loadr_nt PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(loadr_nt PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
set_target_properties(loadr_nt PROPERTIES CXX_STANDARD 20)

# The loader talks to the loader lock, the PEB module list and the unwind
# tables directly, so it needs ntdll by name rather than through the CRT.
target_link_libraries(loadr_nt PUBLIC ntdll)
