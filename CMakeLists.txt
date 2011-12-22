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


SET(MS_PROJECT_NAME maidsafe_encrypt)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.4 FATAL_ERROR)
MESSAGE("================================================================================\n")

GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
ENDIF()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  PROJECT(${MS_PROJECT_NAME})
ELSE()
  STRING(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  PROJECT(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
ENDIF()

SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)


###################################################################################################
# MaidSafe Common and Private library search                                                      #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)
ADD_MAIDSAFE_LIBRARY(MaidSafe-Private)


###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
FILE(GLOB SOURCE_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.cc")
FILE(GLOB HEADER_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.h")
SET(ALL_FILES_ENCRYPT_DIR ${SOURCE_FILES_ENCRYPT_DIR} ${HEADER_FILES_ENCRYPT_DIR})
SOURCE_GROUP("Encrypt Source Files" FILES ${SOURCE_FILES_ENCRYPT_DIR})
SOURCE_GROUP("Encrypt Header Files" FILES ${HEADER_FILES_ENCRYPT_DIR})

####    TESTS    ####
FILE(GLOB SOURCE_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.cc")
FILE(GLOB HEADER_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.h")
SET(ALL_FILES_ENCRYPT_TESTS_DIR ${SOURCE_FILES_ENCRYPT_TESTS_DIR} ${HEADER_FILES_ENCRYPT_TESTS_DIR})
SOURCE_GROUP("Tests Source Files" FILES ${SOURCE_FILES_ENCRYPT_TESTS_DIR})
SOURCE_GROUP("Tests Header Files" FILES ${HEADER_FILES_ENCRYPT_TESTS_DIR})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
MS_ADD_STATIC_LIBRARY(${MS_PROJECT_NAME} ${ALL_FILES_ENCRYPT_DIR})
MS_ADD_EXECUTABLE(TESTencrypt Tests ${ALL_FILES_ENCRYPT_TESTS_DIR})

TARGET_LINK_LIBRARIES(maidsafe_encrypt_static maidsafe_private_static)
TARGET_LINK_LIBRARIES(TESTencrypt maidsafe_encrypt_static gtest_static)

IF(UNIX)
  # This target builds the reference manual using Doxygen
  ADD_CUSTOM_TARGET(Reference COMMAND doxygen WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
ENDIF()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

IF(UNIX)
  IF(NOT APPLE)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
    SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/test_se.cc
                                PROPERTIES COMPILE_FLAGS "-Wno-effc++")

  ENDIF()
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
#  SET_TARGET_PROPERTIES(maidsafe_encrypt_static PROPERTIES COMPILE_FLAGS "-w")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
ADD_STYLE_TEST(${ALL_FILES_ENCRYPT_DIR} ${ALL_FILES_ENCRYPT_TESTS_DIR})
ADD_GTESTS(TESTencrypt)
TEST_SUMMARY_OUTPUT()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()
RENAME_OUTDATED_BUILT_EXES()

SET(MAIDSAFE_ENCRYPT_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/config.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/data_map.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/self_encryptor.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/version.h)

MS_INSTALL_LIBS(maidsafe_encrypt_static)
MS_INSTALL_HEADERS(encrypt ${MAIDSAFE_ENCRYPT_INSTALL_FILES})
MS_INSTALL_EXPORT()
