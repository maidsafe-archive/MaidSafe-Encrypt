#==============================================================================#
#                                                                              #
#  Copyright (c) 2012 MaidSafe.net limited                                     #
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


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(encrypt)

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/encrypt/*.proto")

include(../../cmake_modules/maidsafe_find_openmp.cmake)
include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.cc")
file(GLOB HEADER_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.h")
file(GLOB API_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/encrypt/*.h")
set(ALL_FILES_ENCRYPT_DIR ${SOURCE_FILES_ENCRYPT_DIR} ${HEADER_FILES_ENCRYPT_DIR} ${API_FILES_ENCRYPT_DIR})
source_group("Encrypt Source Files" FILES ${SOURCE_FILES_ENCRYPT_DIR})
source_group("Encrypt Header Files" FILES ${HEADER_FILES_ENCRYPT_DIR})
source_group("Encrypt API Files" FILES ${API_FILES_ENCRYPT_DIR})

####    TESTS    ####
file(GLOB SOURCE_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.cc")
file(GLOB HEADER_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.h")
set(ALL_FILES_ENCRYPT_TESTS_DIR ${SOURCE_FILES_ENCRYPT_TESTS_DIR} ${HEADER_FILES_ENCRYPT_TESTS_DIR})
source_group("Tests Source Files" FILES ${SOURCE_FILES_ENCRYPT_TESTS_DIR})
source_group("Tests Header Files" FILES ${HEADER_FILES_ENCRYPT_TESTS_DIR})

####    STYLE    ####
set(STYLE_FILES ${ALL_FILES_ENCRYPT_DIR} ${ALL_FILES_ENCRYPT_TESTS_DIR})
list(REMOVE_ITEM STYLE_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/data_map.pb.h")
list(REMOVE_ITEM STYLE_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/data_map.pb.cc")

###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(encrypt ${ALL_FILES_ENCRYPT_DIR})
ms_add_executable(TESTencrypt "Tests/Encrypt" ${ALL_FILES_ENCRYPT_TESTS_DIR})

target_link_libraries(maidsafe_encrypt maidsafe_private)
target_link_libraries(TESTencrypt maidsafe_encrypt)

rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)
file(GLOB_RECURSE PROTO_SOURCE_FILES "${PROJECT_SOURCE_DIR}/src/*.pb.cc")
ms_disable_warnings(${PROTO_SOURCE_FILES})

# Enable OpenMP if available
if(OPENMP_FOUND)
  add_definitions(-DMAIDSAFE_OMP_ENABLED)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

if(UNIX AND (NOT APPLE))
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${STYLE_FILES})
add_gtests(TESTencrypt)
add_project_experimental()
test_summary_output()
