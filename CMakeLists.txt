# ============================================================================ #
#                                                                              #
# Copyright [2011] maidsafe.net limited                                        #
#                                                                              #
# Description:  CMakeList for MaidSafe-Encrypt project.                        #
# Created:      2011-01-31                                                     #
# Company:      maidsafe.net limited                                           #
#                                                                              #
# The following source code is property of maidsafe.net limited and is not     #
# meant for external use.  The use of this code is governed by the license     #
# file LICENSE.TXT found in the root of this directory and also on             #
# www.maidsafe.net.                                                            #
#                                                                              #
# You are not free to copy, amend or otherwise use this source code without    #
# the explicit written permission of the board of directors of maidsafe.net.   #
#                                                                              #
# ============================================================================ #


CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
MESSAGE("================================================================================\n")

SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.\nTo see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  SET(PROJECT_NAME MaidSafe-Encrypt)
ELSE()
  SET(PROJECT_NAME MaidSafe-Encrypt_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)


# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

###################################################################################################
# MaidSafe Common library search                                                                  #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)

###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/version.h)

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
FILE(GLOB SOURCE_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/*.cc")
FILE(GLOB HEADER_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/*.h")
SET(ALL_FILES ${SOURCE_FILES} ${HEADER_FILES})

####    TESTS    ####
FILE(GLOB ALL_FILES_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/tests/*.cc" "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/tests/*.h")
LIST(REMOVE_ITEM ALL_FILES_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/tests/encrypt_demo.cc")

###################################################################################################
# All Platforms:  Create libs and executables                                                     #
###################################################################################################
ADD_LIBRARY(encrypt_static STATIC ${ALL_FILES})
SET_TARGET_PROPERTIES(encrypt_static PROPERTIES OUTPUT_NAME maidsafe_encrypt)
ADD_EXECUTABLE(TESTencrypt ${ALL_FILES_TESTS_DIR})
ADD_EXECUTABLE(DEMOencrypt "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/tests/encrypt_demo.cc")

RENAME_EXECUTABLE(TESTencrypt)
RENAME_EXECUTABLE(DEMOencrypt)

TARGET_LINK_LIBRARIES(encrypt_static
                        maidsafe_common_static
                        glog_static
                        boost_filesystem
                        boost_serialization
                        boost_system)
TARGET_LINK_LIBRARIES(TESTencrypt encrypt_static gtest_static)
TARGET_LINK_LIBRARIES(DEMOencrypt encrypt_static)

IF(UNIX)
  # This target builds the reference manual using Doxygen
  ADD_CUSTOM_TARGET(Reference COMMAND doxygen WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
ENDIF()

###################################################################################################
# Compiler and linker flags - after all targets declared                                          #
###################################################################################################
INCLUDE(maidsafe_standard_flags)
IF(MSVC)
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Oi /GF ") #  /wd4503
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Oi /arch:SSE") #  /wd4503
  SET_TARGET_PROPERTIES(encrypt_static PROPERTIES
                          STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")
  SET_TARGET_PROPERTIES(TESTencrypt DEMOencrypt PROPERTIES
                          LINK_FLAGS "/STACK:1048576"
                          LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO")

#  SET_TARGET_PROPERTIES(encrypt_static PROPERTIES
#                            COMPILE_FLAGS "/D_VC80_UPGRADE=0x0710"
#                            LINK_FLAGS "/STACK:1048576"
#                            LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
#                            LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
#                            LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
#                            LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
#  SET_TARGET_PROPERTIES(TESTencrypt DEMOencrypt PROPERTIES
#                            COMPILE_FLAGS "/D_CONSOLE /D_VC80_UPGRADE=0x0710 /D_MBCS"
#                            LINK_FLAGS "/STACK:1048576"
#                            LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${TEST_LINKER_LIBS_DIRS_RELEASE}"
#                            LINK_FLAGS_DEBUG "${TEST_LINKER_LIBS_DIRS_DEBUG}"
#                            LINK_FLAGS_RELWITHDEBINFO "/LTCG ${TEST_LINKER_LIBS_DIRS_DEBUG}"
#                            LINK_FLAGS_MINSIZEREL "/LTCG ${TEST_LINKER_LIBS_DIRS_DEBUG}")
ELSEIF(UNIX)
  IF(APPLE)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOSX")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINUX -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -Wredundant-decls -Wuninitialized -Wunused-function")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -fno-stack-protector")
  ENDIF()
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wuninitialized")
  SET_TARGET_PROPERTIES(encrypt_static PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions")
ENDIF()

###################################################################################################
# Tests                                                                                           #
###################################################################################################
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${ALL_FILES} ${ALL_FILES_TESTS_DIR} "${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/tests/encrypt_demo.cc")
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${PROJECT_SOURCE_DIR})
    ADD_TEST(STYLE_CHECK ${MaidSafeCommon_TOOLS_DIR}/run_cpplint.bat ${STYLE_CHECK_SOURCE})
  ENDIF()
  SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
ENDIF()

ADD_GTESTS(TESTencrypt)

TEST_SUMMARY_OUTPUT()

###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()

SET(MAIDSAFE_ENCRYPT_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/config.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/data_map.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/self_encryption.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/self_encryption_stream.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe-encrypt/version.h)

SET(EXPORT_NAME encrypt)
INSTALL(TARGETS encrypt_static EXPORT ${EXPORT_NAME} ARCHIVE DESTINATION lib)
INSTALL(FILES ${MAIDSAFE_ENCRYPT_INSTALL_FILES} DESTINATION include/maidsafe/maidsafe-encrypt)
INSTALL(EXPORT ${EXPORT_NAME} DESTINATION share/maidsafe)
ADD_VERSION_INFO_TO_INSTALLED_FILE()


IF(CMAKE_BUILD_TYPE MATCHES "Release")
  SET(CPACK_PACKAGE_VERSION_MAJOR "0")
  SET(CPACK_PACKAGE_VERSION_MINOR "1")
  SET(CPACK_PACKAGE_VERSION_PATCH ${pddate})
  SET(CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH})
  SET(CPACK_PACKAGE_NAME "maidsafe_encrypt")
  SET(CPACK_PACKAGE_CONTACT "dev@maidsafe.net")
  SET(CPACK_PACKAGE_VENDOR "maidsafe.net")
  SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MaidSafe-Encrypt")
  SET(CPACK_PACKAGE_INSTALL_DIRECTORY "maidsafe-encrypt")
#  SET(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/docs/readme.txt")
  IF(UNIX)
    SET(CPACK_SET_DESTDIR on)
    SET(CPACK_GENERATOR DEB;RPM;TGZ)
    MESSAGE("Package install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
    MESSAGE("================================================================================")
  ELSE()
    SET(CPACK_GENERATOR ZIP)
  ENDIF()
  INCLUDE(CPack)
ELSE()
  FILE(REMOVE ${PROJECT_BINARY_DIR}/CPackConfig.cmake ${PROJECT_BINARY_DIR}/CPackSourceConfig.cmake)
ENDIF()
