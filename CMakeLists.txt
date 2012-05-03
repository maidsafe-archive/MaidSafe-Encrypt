#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


set(MS_PROJECT_NAME maidsafe_encrypt)

cmake_minimum_required(VERSION 2.8.4 FATAL_ERROR)
message("================================================================================\n")

get_filename_component(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
if(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  set(CMAKE_BUILD_TYPE_DIR Release)
elseif(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  set(CMAKE_BUILD_TYPE_DIR Debug)
  set(KDEV 1)
endif()

if(NOT ${CMAKE_C_COMPILER_WORKS})
  message(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
endif()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
if((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  project(${MS_PROJECT_NAME})
else()
  string(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  project(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
endif()

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)


###################################################################################################
# MaidSafe Common and Private library search                                                      #
###################################################################################################
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
include(maidsafe_find_common)
add_maidsafe_library(MaidSafe-Private)


###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
include(maidsafe_standard_setup)
handle_versions(${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.cc")
file(GLOB HEADER_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.h")
set(ALL_FILES_ENCRYPT_DIR ${SOURCE_FILES_ENCRYPT_DIR} ${HEADER_FILES_ENCRYPT_DIR})
source_group("Encrypt Source Files" FILES ${SOURCE_FILES_ENCRYPT_DIR})
source_group("Encrypt Header Files" FILES ${HEADER_FILES_ENCRYPT_DIR})

####    TESTS    ####
file(GLOB SOURCE_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.cc")
file(GLOB HEADER_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.h")
set(ALL_FILES_ENCRYPT_TESTS_DIR ${SOURCE_FILES_ENCRYPT_TESTS_DIR} ${HEADER_FILES_ENCRYPT_TESTS_DIR})
source_group("Tests Source Files" FILES ${SOURCE_FILES_ENCRYPT_TESTS_DIR})
source_group("Tests Header Files" FILES ${HEADER_FILES_ENCRYPT_TESTS_DIR})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(${MS_PROJECT_NAME} ${ALL_FILES_ENCRYPT_DIR})
ms_add_executable(TESTencrypt Tests ${ALL_FILES_ENCRYPT_TESTS_DIR})

target_link_libraries(maidsafe_encrypt_static maidsafe_private_static)
target_link_libraries(TESTencrypt maidsafe_encrypt_static gtest_static)

if(UNIX)
  # This target builds the reference manual using Doxygen
  add_custom_target(Reference COMMAND doxygen WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endif()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

if(UNIX)
  if(NOT APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
    set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/test_se.cc
                                PROPERTIES COMPILE_FLAGS "-Wno-effc++")

  endif()
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
#  set_target_properties(maidsafe_encrypt_static PROPERTIES COMPILE_FLAGS "-w")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${ALL_FILES_ENCRYPT_DIR} ${ALL_FILES_ENCRYPT_TESTS_DIR})
add_gtests(TESTencrypt)
test_summary_output()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
final_message()
rename_outdated_built_exes()

set(MAIDSAFE_ENCRYPT_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/config.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/data_map.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/self_encryptor.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/version.h)

ms_install_libs(maidsafe_encrypt_static)
ms_install_headers(encrypt ${MAIDSAFE_ENCRYPT_INSTALL_FILES})
ms_install_export()
