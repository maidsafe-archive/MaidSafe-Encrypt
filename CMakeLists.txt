# ============================================================================ #
#                                                                              #
# Copyright [2010] maidsafe.net limited                                        #
#                                                                              #
# Description:  CMakeList for PD project.                                      #
# Version:      1.0                                                            #
# Created:      2010-04-15-21.01.30                                            #
# Revision:     none                                                           #
# Compiler:     N/A                                                            #
# Author:       Team                                                           #
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
SET(CMAKE_CACHEFILE "${CMAKE_CACHEFILE_DIR}/CMakeCache.txt")
IF(WIN32)
  STRING(REPLACE "/" "\\" CMAKE_CACHEFILE ${CMAKE_CACHEFILE})
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.  Run:\n")
SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"Visual Studio 9 2008\"\n\n")
ELSEIF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE()
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - MinGW Makefiles\"\n\n")
ENDIF()



SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF(CMAKE_BUILD_TYPE_DIR MATCHES "Release")
  SET(PROJECT_NAME PD)
ELSE()
  SET(PROJECT_NAME PD_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)

FIND_PROGRAM(GITCOMMAND git PATHS ENV ProgramFiles PATH_SUFFIXES "Git/bin")
SET(UPDATE_TYPE git)
SET(UPDATE_COMMAND "${GITCOMMAND}")

# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

SET(${PROJECT_NAME}_ROOT ${PROJECT_SOURCE_DIR})
SET(${PROJECT_NAME}_SOURCE_DIR ${${PROJECT_NAME}_ROOT}/src)
SET(SOURCE_DIR ${${PROJECT_NAME}_ROOT}/src)

IF(NOT MAIDSAFE_TEST_TYPE)
  SET(MAIDSAFE_TEST_TYPE "BEH" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
  SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: Behavioural")
ELSE()
  IF(${MAIDSAFE_TEST_TYPE} MATCHES _)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: All")
  ELSEIF(${MAIDSAFE_TEST_TYPE} MATCHES BEH)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: Behavioural")
  ELSEIF(${MAIDSAFE_TEST_TYPE} MATCHES FUNC)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: Functional")
  ELSE()
    SET(MAIDSAFE_TEST_TYPE "_" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: All")
  ENDIF()
ENDIF()

ENABLE_TESTING()

IF(APPLE)
  SET(CMAKE_OSX_SYSROOT "/")
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  IF(MSVC)
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is OK to release.")
    MESSAGE("-----------------------------------------------------------------------")
  ENDIF()
ELSE()
  IF(MSVC)
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is NOT OK to release.")
    MESSAGE("---------------------------------------------------------------------------")
  ENDIF()
ENDIF()


# setup a single target path for libraries and executables -
# this avoids copying all the dlls and exes together
UNSET(CMAKE_RUNTIME_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_LIBRARY_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY CACHE)
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Executable target dir (x64).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Shared library target dir (x64).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Static library target dir (x64).")
  ELSE()
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Executable target dir (win32).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Shared library target dir (win32).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Static library target dir (win32).")
  ENDIF()
ELSE()
  SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Executable target dir.")
  SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Shared library target dir.")
  SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Static library target dir.")
ENDIF()

SET(CMAKE_DEBUG_POSTFIX _d)
SET(CMAKE_RELWITHDEBINFO_POSTFIX _rwdi)
SET(CMAKE_MINSIZEREL_POSTFIX _msr)

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(TEST_POSTFIX ${CMAKE_DEBUG_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
  SET(TEST_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
  SET(TEST_POSTFIX ${CMAKE_MINSIZEREL_POSTFIX})
ENDIF()

# Create CTestCustom.cmake to avoid inclusion of coverage results from third-party code
FILE(WRITE ${${PROJECT_NAME}_BINARY_DIR}/CTestCustom.cmake "SET(CTEST_CUSTOM_COVERAGE_EXCLUDE \${CTEST_CUSTOM_COVERAGE_EXCLUDE} \"examples/\" \"*.pb.*\" \"tests/\" \"tools/\" \"cppsqlite3\")\n\n")

###################################################################################################
# Set default directories to be searched for included files and libs                              #
###################################################################################################
IF(DEFINED ADD_LIBRARY_DIR)
  IF(DEFAULT_LIBRARY_DIR)
    LIST(REMOVE_DUPLICATES DEFAULT_LIBRARY_DIR)
  ENDIF()
  SET(DEFAULT_LIBRARY_DIR ${DEFAULT_LIBRARY_DIR} ${ADD_LIBRARY_DIR} CACHE PATH "Path to libraries directories" FORCE)
ENDIF()

IF(MSVC)
  SET(CMAKE_INCLUDE_PATH "c:\\msvc\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\msvc\\lib" ${DEFAULT_LIBRARY_DIR})
ELSEIF(WIN32) # MinGW builds
  SET(CMAKE_INCLUDE_PATH "c:\\MinGW\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\MinGW\\lib" ${DEFAULT_LIBRARY_DIR})
ELSE()
  SET(CMAKE_INCLUDE_PATH "/usr/local/include /usr/include")
  SET(CMAKE_LIBRARY_PATH "/usr/local/lib /usr/lib" ${DEFAULT_LIBRARY_DIR})
ENDIF()


# Function to help set <MODULE>_ROOT_DIR for use of following Find Modules
# Example: For PROJ_VARIABLE set to "BOOST_ROOT_DIR", PROJ_SEARCH_REGEX set to "boost",
# and PROJ_SEARCH_DIR set to c:\msvc, if "boost_1_41_0" and "boost_1_42_0"
# are both subdirectories of c:\msvc, then BOOST_ROOT_DIR_CACHED is set
# and cached to c:\msvc\boost_1_42_0
FUNCTION(FIND_THIRD_PARTY_PROJECT PROJ_VARIABLE PROJ_SEARCH_REGEX PROJ_SEARCH_DIR)
  UNSET(${ARGV0}_CACHED CACHE)
  STRING(REPLACE "/" "\\" PROJ_SEARCH_DIR ${PROJ_SEARCH_DIR})
  EXECUTE_PROCESS(COMMAND CMD /C DIR ${PROJ_SEARCH_DIR} /A:D /O:-N /B OUTPUT_VARIABLE THIRD_PARTY_ROOT_DIRS ERROR_VARIABLE ERR_VAR)
  IF(NOT ERR_VAR)
    STRING(REGEX MATCH "${PROJ_SEARCH_REGEX}[^\n]*" THIRD_PARTY_ROOT_DIR "${THIRD_PARTY_ROOT_DIRS}")
    IF(NOT THIRD_PARTY_ROOT_DIR)
      SET(${ARGV0})
    ELSE()
      SET(${ARGV0}_CACHED "${PROJ_SEARCH_DIR}\\${THIRD_PARTY_ROOT_DIR}" CACHE PATH "")
    ENDIF()
  ENDIF()
ENDFUNCTION()

###################################################################################################
# Boost libraries search                                                                          #
###################################################################################################
SET(REQUIRED_BOOST_COMPONENTS date_time filesystem regex system thread)
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindBoost.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Boost_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Boost_LIBRARY_DIRS})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Boost_LIBRARY_DIRS})

###################################################################################################
# QT library search                                                                               #
###################################################################################################
# Including this file sets up environment with correct dirs / flags - no need to explicitly set
# anything else other than linking to QT_LIBRARIES as appropriate.
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindQt4.cmake)
IF (NOT WIN32)
  # these are required for static builds
  SET(QT_LIBRARIES ${QT_LIBRARIES} z Xext X11 pcre xcb Xau Xdmcp)
ENDIF()

###################################################################################################
# Google Test library search                                                                      #
###################################################################################################
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindGtest.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gtest_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gtest_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Gtest_LIBRARY_DIR_DEBUG})
IF(NOT WIN32)
  SET(Gtest_LIBRARY "${Gtest_LIBRARY};pthread")
ENDIF()

###################################################################################################
# Google Mock library search                                                                      #
###################################################################################################
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindGmock.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gmock_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gmock_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Gmock_LIBRARY_DIR_DEBUG})

###################################################################################################
# Google Log library search - Glog can't currently be compiled on Windows with MinGW              #
###################################################################################################
IF((NOT WIN32) OR MSVC)
  INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindGlog.cmake)
  IF(Glog_FOUND)
    SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Glog_INCLUDE_DIR})
    SET(LIBS_DIRS ${LIBS_DIRS} ${Glog_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Glog_LIBRARY_DIR_DEBUG})
  ENDIF()
ENDIF()

###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB_RECURSE PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.proto")
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindProtobuf.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Protobuf_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Protobuf_LIBRARY_DIR_DEBUG})

###################################################################################################
# Google BreakPad library search                                                                  #
###################################################################################################
#IF((UNIX AND NOT APPLE) OR MSVC)
#  INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindBreakpad.cmake)
#  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Breakpad_INCLUDE_DIR})
#  SET(LIBS_DIRS ${LIBS_DIRS} ${Breakpad_LIBRARY_DIR})
#  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Breakpad_LIBRARY_DIR_DEBUG})
#ENDIF()

###################################################################################################
# Python library search                                                                           #
###################################################################################################
UNSET(PYTHON_EXECUTABLE CACHE)
INCLUDE(FindPythonInterp)
FIND_PACKAGE(PythonInterp)
IF(PYTHONINTERP_FOUND)
  MESSAGE("-- Found python executable: style checking enabled.")
ELSE()
  MESSAGE("-- Didn't find python executable: style checking disabled.")
ENDIF()

###################################################################################################
# Dokan / Fuse library search                                                                     #
###################################################################################################
IF(WIN32)
  INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindDokan.cmake)
  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Dokan_INCLUDE_DIR})
  SET(LIBS_DIRS ${LIBS_DIRS} ${Dokan_LIBRARY_DIR})
  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Dokan_LIBRARY_DIR})
  SET(Fuse_LIBRARY ${Dokan_LIBRARY})
ELSE()
  FIND_LIBRARY(Fuse_LIBRARY libfuse.a)
  IF(Fuse_LIBRARY)
    MESSAGE("-- Found library ${Fuse_LIBRARY}")
    GET_FILENAME_COMPONENT(Fuse_LIBRARY_DIR ${Fuse_LIBRARY} PATH)
    SET(LIBS_DIRS ${LIBS_DIRS} ${Fuse_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Fuse_LIBRARY_DIR})
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find library libfuse.a.")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}  Run\n${ERROR_MESSAGE_CMAKE_PATH} -DADD_LIBRARY_DIR=<Path to libfuse.a directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ENDIF()

###################################################################################################
# All other libraries (except maidsafe_dht) search                                                #
###################################################################################################
IF(UNIX)
  SET(OTHER_LIBS dl pthread)
  IF(NOT APPLE)
    SET(OTHER_LIBS rt c m ${OTHER_LIBS})
  ENDIF()
ELSEIF(WIN32)
  IF(MSVC)
    SET(OTHER_LIBS ws2_32 odbc32 odbccp32 WSock32 IPHlpApi)
  ELSE()
    SET(OTHER_LIBS advapi32 ws2_32 iphlpapi mswsock)
  ENDIF()
ENDIF()
FOREACH(library ${OTHER_LIBS})
  FIND_LIBRARY(CURRENT_LIB ${library})
  IF(CURRENT_LIB)
    MESSAGE("-- Found library ${CURRENT_LIB}")
    GET_FILENAME_COMPONENT(CURRENT_LIBRARY_DIR ${CURRENT_LIB} PATH)
    SET(LIBS_DIRS ${LIBS_DIRS} ${CURRENT_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${CURRENT_LIBRARY_DIR})
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find library ${library}.")
    IF(MSVC)
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}\nRun cmake from a Visual Studio Command Prompt.")
    ELSE()
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}  Run\n${ERROR_MESSAGE_CMAKE_PATH} -DADD_LIBRARY_DIR=<Path to ${library} directory>")
    ENDIF()
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  UNSET(CURRENT_LIB CACHE)
ENDFOREACH()

###################################################################################################
# maidsafe-dht, cryptopp and udt library search                                                   #
###################################################################################################
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindMaidsafeDht.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${maidsafe_dht_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${maidsafe_dht_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${maidsafe_dht_LIBRARY_DIR_DEBUG})


LIST(REMOVE_DUPLICATES LIBS_DIRS)
LIST(REMOVE_DUPLICATES LIBS_DIRS_DEBUG)
LINK_DIRECTORIES(${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

INCLUDE_DIRECTORIES(${${PROJECT_NAME}_SOURCE_DIR})
INCLUDE_DIRECTORIES(${${PROJECT_NAME}_BINARY_DIR})
LIST(REMOVE_DUPLICATES INCLUDE_DIRS)
INCLUDE_DIRECTORIES(AFTER SYSTEM ${INCLUDE_DIRS})

MESSAGE("================================================================================")

###################################################################################################
# Cleanup of temporary test folders                                                               #
###################################################################################################
IF(WIN32)
  IF(NOT CLEAN_TEMP)
    SET(CLEAN_TEMP "OFF" CACHE INTERNAL "Cleanup of temp test folders, options are: ONCE, OFF, ALWAYS" FORCE)
  ENDIF(NOT CLEAN_TEMP)
  EXECUTE_PROCESS(COMMAND CMD /C ECHO %TEMP% OUTPUT_VARIABLE temp_path OUTPUT_STRIP_TRAILING_WHITESPACE)
  STRING(REPLACE "\\" "/" temp_path ${temp_path})
  FILE(GLOB temp_dirs ${temp_path}/maidsafe_Test*)
  LIST(LENGTH temp_dirs temp_dir_count)
  IF(NOT ${temp_dir_count} EQUAL 0)
    MESSAGE("")
    IF(CLEAN_TEMP MATCHES ONCE OR CLEAN_TEMP MATCHES ALWAYS)
      MESSAGE("Cleaning up temporary test folders.\n")
      FOREACH(temp_dir ${temp_dirs})
        FILE(REMOVE_RECURSE ${temp_dir})
        MESSAGE("-- Removed ${temp_dir}")
      ENDFOREACH()
    ELSE()
      MESSAGE("The following temporary test folders could be cleaned up:\n")
      FOREACH(temp_dir ${temp_dirs})
        MESSAGE("-- Found ${temp_dir}")
      ENDFOREACH()
      MESSAGE("")
      MESSAGE("To cleanup, run cmake ../.. -DCLEAN_TEMP=ONCE or cmake ../.. -DCLEAN_TEMP=ALWAYS")
    ENDIF()
    MESSAGE("================================================================================")
  ENDIF()
  IF(NOT CLEAN_TEMP MATCHES ALWAYS)
    SET(CLEAN_TEMP "OFF" CACHE INTERNAL "Cleanup of temp test folders, options are: ONCE, OFF, ALWAYS" FORCE)
  ENDIF()
ENDIF()

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
SET(SRC_MAIDSAFE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe")

####    CODE    ####
FILE(GLOB SOURCE_FILES_CLIENT_DIR "${SRC_MAIDSAFE}/client/*.cc")
FILE(GLOB HEADER_FILES_CLIENT_DIR "${SRC_MAIDSAFE}/client/*.h")
SET(ALL_FILES_CLIENT_DIR ${SOURCE_FILES_CLIENT_DIR} ${HEADER_FILES_CLIENT_DIR})
SET(STYLE_CLIENT ${ALL_FILES_CLIENT_DIR})
LIST(REMOVE_ITEM ALL_FILES_CLIENT_DIR "${SRC_MAIDSAFE}/client/main.cc")
SET(ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR ${ALL_FILES_CLIENT_DIR})
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/maidstoremanager.cc")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/maidstoremanager.h")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/clientrpc.cc")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/clientrpc.h")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/storemanagertaskshandler.cc")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/storemanagertaskshandler.h")
LIST(REMOVE_ITEM ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR "${SRC_MAIDSAFE}/client/opdata.h")
SOURCE_GROUP("client Source Files" FILES ${SOURCE_FILES_CLIENT_DIR})
SOURCE_GROUP("client Header Files" FILES ${HEADER_FILES_CLIENT_DIR})


FILE(GLOB SOURCE_FILES_CLIENT_FILESYSTEM_DIR "${SRC_MAIDSAFE}/client/filesystem/*.cc")
FILE(GLOB HEADER_FILES_CLIENT_FILESYSTEM_DIR "${SRC_MAIDSAFE}/client/filesystem/*.h")
SET(ALL_FILES_CLIENT_FILESYSTEM_DIR ${SOURCE_FILES_CLIENT_FILESYSTEM_DIR} ${HEADER_FILES_CLIENT_FILESYSTEM_DIR})
SET(STYLE_CLIENT_FILESYSTEM ${ALL_FILES_CLIENT_FILESYSTEM_DIR})
SOURCE_GROUP("client filesystem Source Files" FILES ${SOURCE_FILES_CLIENT_FILESYSTEM_DIR})
SOURCE_GROUP("client filesystem Header Files" FILES ${HEADER_FILES_CLIENT_FILESYSTEM_DIR})

FILE(GLOB SOURCE_FILES_COMMON_DIR "${SRC_MAIDSAFE}/common/*.c*")
FILE(GLOB HEADER_FILES_COMMON_DIR "${SRC_MAIDSAFE}/common/*.h")
SET(ALL_FILES_COMMON_DIR ${SOURCE_FILES_COMMON_DIR} ${HEADER_FILES_COMMON_DIR})
SET(STYLE_COMMON ${ALL_FILES_COMMON_DIR})
LIST(REMOVE_ITEM STYLE_COMMON "${SRC_MAIDSAFE}/common/sqlite3.c")
LIST(REMOVE_ITEM STYLE_COMMON "${SRC_MAIDSAFE}/common/sqlite3.h")
SOURCE_GROUP("common Source Files" FILES ${SOURCE_FILES_COMMON_DIR})
SOURCE_GROUP("common Header Files" FILES ${HEADER_FILES_COMMON_DIR})


FILE(GLOB SOURCE_FILES_DEDUP_ANALYSER_DIR "${SRC_MAIDSAFE}/dedup_analyser/*.cc")
FILE(GLOB HEADER_FILES_DEDUP_ANALYSER_DIR "${SRC_MAIDSAFE}/dedup_analyser/*.h")
SET(STYLE_DEDUP_ANALYSER ${SOURCE_FILES_DEDUP_ANALYSER_DIR} ${HEADER_FILES_DEDUP_ANALYSER_DIR})
QT4_WRAP_CPP(MOC_FILES_DEDUP_ANALYSER_DIR ${HEADER_FILES_DEDUP_ANALYSER_DIR})
SOURCE_GROUP("dedup_analyser Source Files" FILES ${SOURCE_FILES_DEDUP_ANALYSER_DIR})
SOURCE_GROUP("dedup_analyser Header Files" FILES ${HEADER_FILES_DEDUP_ANALYSER_DIR})
SOURCE_GROUP("dedup_analyser MOC Files" FILES ${MOC_FILES_DEDUP_ANALYSER_DIR})

FILE(GLOB SOURCE_FILES_DEDUP_ANALYSER_WIDGETS_DIR "${SRC_MAIDSAFE}/dedup_analyser/widgets/*.cc")
FILE(GLOB HEADER_FILES_DEDUP_ANALYSER_WIDGETS_DIR "${SRC_MAIDSAFE}/dedup_analyser/widgets/*.h")
FILE(GLOB HEADER_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR "${SRC_MAIDSAFE}/dedup_analyser/qwt_widgets/*.h")
FILE(GLOB SOURCE_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR "${SRC_MAIDSAFE}/dedup_analyser/qwt_widgets/*.cc")

SET(STYLE_DEDUP_ANALYSER ${STYLE_DEDUP_ANALYSER} ${SOURCE_FILES_DEDUP_ANALYSER_WIDGETS_DIR} ${HEADER_FILES_DEDUP_ANALYSER_WIDGETS_DIR} ${SOURCE_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR} ${HEADER_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR})

QT4_WRAP_CPP(MOC_FILES_DEDUP_ANALYSER_WIDGETS_DIR ${HEADER_FILES_DEDUP_ANALYSER_WIDGETS_DIR})
QT4_WRAP_CPP(MOC_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR ${HEADER_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR})
SOURCE_GROUP("dedup_analyser widgets Source Files" FILES ${SOURCE_FILES_DEDUP_ANALYSER_WIDGETS_DIR})
SOURCE_GROUP("dedup_analyser widgets Header Files" FILES ${HEADER_FILES_DEDUP_ANALYSER_WIDGETS_DIR})
SOURCE_GROUP("dedup_analyser widgets MOC Files" FILES ${MOC_FILES_DEDUP_ANALYSER_WIDGETS_DIR})
SOURCE_GROUP("dedup_analyser qwt widgets MOC Files" FILES ${MOC_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR})
SOURCE_GROUP("dedup_analyser qwt widgets Source files" FILES ${SOURCE_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR})
SOURCE_GROUP("dedup_analyser qwt widgets Header files" FILES ${HEADER_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR})

FILE(GLOB QRC_FILES_DEDUP_ANALYSER_RESOURCES_DIR "${SRC_MAIDSAFE}/dedup_analyser/resources/*.qrc")
QT4_ADD_RESOURCES(RESOURCE_FILES_DEDUP_ANALYSER_RESOURCES_DIR ${QRC_FILES_DEDUP_ANALYSER_RESOURCES_DIR})
SOURCE_GROUP("dedup_analyser Resource Files" FILES ${RESOURCE_FILES_DEDUP_ANALYSER_RESOURCES_DIR})

FILE(GLOB UI_FILES_DEDUP_ANALYSER_UI_DIR "${SRC_MAIDSAFE}/dedup_analyser/ui/*.ui")
QT4_WRAP_UI(UIC_FILES_DEDUP_ANALYSER_UI_DIR ${UI_FILES_DEDUP_ANALYSER_UI_DIR})
SOURCE_GROUP("dedup_analyser UI Files" FILES ${UI_FILES_DEDUP_ANALYSER_UI_DIR})
SOURCE_GROUP("dedup_analyser UI Compiled Files" FILES ${UIC_FILES_DEDUP_ANALYSER_UI_DIR})

SET(ALL_DEDUP_ANALYSER_SOURCE_FILES
      ${SOURCE_FILES_DEDUP_ANALYSER_DIR} ${MOC_FILES_DEDUP_ANALYSER_DIR}
      ${SOURCE_FILES_DEDUP_ANALYSER_WIDGETS_DIR} ${MOC_FILES_DEDUP_ANALYSER_WIDGETS_DIR}
      ${RESOURCE_FILES_DEDUP_ANALYSER_RESOURCES_DIR} ${UI_FILES_DEDUP_ANALYSER_UI_DIR} ${UIC_FILES_DEDUP_ANALYSER_UI_DIR} 
      ${SOURCE_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR} ${MOC_FILES_DEDUP_ANALYSER_QWTWIDGETS_DIR})

SET(ALL_DEDUP_ANALYSER_HEADER_FILES
      ${HEADER_FILES_DEDUP_ANALYSER_DIR}
      ${HEADER_FILES_DEDUP_ANALYSER_WIDGETS_DIR})


IF(WIN32)
  FILE(GLOB SOURCE_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/windows/*.cc")
  FILE(GLOB HEADER_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/windows/*.h")
ELSE()
  FILE(GLOB SOURCE_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/linux/*.cc")
  FILE(GLOB HEADER_FILES_FUSE_DIR "${SRC_MAIDSAFE}/fuse/linux/*.h")
ENDIF()
SET(ALL_FILES_FUSE_DIR ${SOURCE_FILES_FUSE_DIR} ${HEADER_FILES_FUSE_DIR})
SET(STYLE_FUSE ${ALL_FILES_FUSE_DIR})
SOURCE_GROUP("fuse Source Files" FILES ${SOURCE_FILES_FUSE_DIR})
SOURCE_GROUP("fuse Header Files" FILES ${HEADER_FILES_FUSE_DIR})

FILE(GLOB SOURCE_FILES_LIFESTUFF_DIR "${SRC_MAIDSAFE}/lifestuff/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_DIR "${SRC_MAIDSAFE}/lifestuff/*.h")
QT4_WRAP_CPP(MOC_FILES_LIFESTUFF_DIR ${HEADER_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("lifestuff Source Files" FILES ${SOURCE_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("lifestuff Header Files" FILES ${HEADER_FILES_LIFESTUFF_DIR})
SOURCE_GROUP("lifestuff MOC Files" FILES ${MOC_FILES_LIFESTUFF_DIR})

FILE(GLOB SOURCE_FILES_LIFESTUFF_CLIENT_DIR "${SRC_MAIDSAFE}/lifestuff/client/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_CLIENT_DIR "${SRC_MAIDSAFE}/lifestuff/client/*.h")
QT4_WRAP_CPP(MOC_FILES_LIFESTUFF_CLIENT_DIR ${HEADER_FILES_LIFESTUFF_CLIENT_DIR})
SOURCE_GROUP("lifestuff client Source Files" FILES ${SOURCE_FILES_LIFESTUFF_CLIENT_DIR})
SOURCE_GROUP("lifestuff client Header Files" FILES ${HEADER_FILES_LIFESTUFF_CLIENT_DIR})
SOURCE_GROUP("lifestuff client MOC Files" FILES ${MOC_FILES_LIFESTUFF_CLIENT_DIR})

FILE(GLOB SOURCE_FILES_LIFESTUFF_WIDGETS_DIR "${SRC_MAIDSAFE}/lifestuff/widgets/*.cc")
FILE(GLOB HEADER_FILES_LIFESTUFF_WIDGETS_DIR "${SRC_MAIDSAFE}/lifestuff/widgets/*.h")
SET(SOURCE_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR ${SOURCE_FILES_LIFESTUFF_WIDGETS_DIR})
SET(HEADER_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR ${HEADER_FILES_LIFESTUFF_WIDGETS_DIR})
LIST(REMOVE_ITEM SOURCE_FILES_LIFESTUFF_WIDGETS_DIR "${SRC_MAIDSAFE}/lifestuff/widgets/file_browser.cc")
LIST(REMOVE_ITEM HEADER_FILES_LIFESTUFF_WIDGETS_DIR "${SRC_MAIDSAFE}/lifestuff/widgets/file_browser.h")
QT4_WRAP_CPP(MOC_FILES_LIFESTUFF_WIDGETS_DIR ${HEADER_FILES_LIFESTUFF_WIDGETS_DIR})
QT4_WRAP_CPP(MOC_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR ${HEADER_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR})
SOURCE_GROUP("lifestuff widgets Source Files" FILES ${SOURCE_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR})
SOURCE_GROUP("lifestuff widgets Header Files" FILES ${HEADER_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR})
SOURCE_GROUP("lifestuff widgets MOC Files" FILES ${MOC_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR})

FILE(GLOB QRC_FILES_LIFESTUFF_RESOURCES_DIR "${SRC_MAIDSAFE}/lifestuff/resources/*.qrc")
QT4_ADD_RESOURCES(RESOURCE_FILES_LIFESTUFF_RESOURCES_DIR ${QRC_FILES_LIFESTUFF_RESOURCES_DIR})
SOURCE_GROUP("lifestuff Resource Files" FILES ${RESOURCE_FILES_LIFESTUFF_RESOURCES_DIR})

FILE(GLOB UI_FILES_LIFESTUFF_UI_DIR "${SRC_MAIDSAFE}/lifestuff/ui/*.ui")
QT4_WRAP_UI(UIC_FILES_LIFESTUFF_UI_DIR ${UI_FILES_LIFESTUFF_UI_DIR})
SOURCE_GROUP("lifestuff UI Files" FILES ${UI_FILES_LIFESTUFF_UI_DIR})
SOURCE_GROUP("lifestuff UI Compiled Files" FILES ${UIC_FILES_LIFESTUFF_UI_DIR})

SET(ALL_LIFESTUFF_SOURCE_FILES
      ${SOURCE_FILES_LIFESTUFF_DIR} ${MOC_FILES_LIFESTUFF_DIR}
      ${SOURCE_FILES_LIFESTUFF_CLIENT_DIR} ${MOC_FILES_LIFESTUFF_CLIENT_DIR}
      ${SOURCE_FILES_LIFESTUFF_WIDGETS_DIR} ${MOC_FILES_LIFESTUFF_WIDGETS_DIR}
      ${RESOURCE_FILES_LIFESTUFF_RESOURCES_DIR} ${UI_FILES_LIFESTUFF_UI_DIR} ${UIC_FILES_LIFESTUFF_UI_DIR})
SET(ALL_LIFESTUFF_HEADER_FILES
      ${HEADER_FILES_LIFESTUFF_DIR}
      ${HEADER_FILES_LIFESTUFF_CLIENT_DIR}
      ${HEADER_FILES_LIFESTUFF_WIDGETS_DIR})
SET(ALL_LIFESTUFF_LIGHT_SOURCE_FILES
      ${SOURCE_FILES_LIFESTUFF_DIR} ${MOC_FILES_LIFESTUFF_DIR}
      ${SOURCE_FILES_LIFESTUFF_CLIENT_DIR} ${MOC_FILES_LIFESTUFF_CLIENT_DIR}
      ${SOURCE_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR} ${MOC_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR}
      ${RESOURCE_FILES_LIFESTUFF_RESOURCES_DIR} ${UI_FILES_LIFESTUFF_UI_DIR} ${UIC_FILES_LIFESTUFF_UI_DIR})
SET(ALL_LIFESTUFF_LIGHT_HEADER_FILES
      ${HEADER_FILES_LIFESTUFF_DIR}
      ${HEADER_FILES_LIFESTUFF_CLIENT_DIR}
      ${HEADER_FILES_LIFESTUFF_LIGHT_WIDGETS_DIR})


FILE(GLOB SOURCE_FILES_VAULT_DIR "${SRC_MAIDSAFE}/vault/*.cc")
FILE(GLOB HEADER_FILES_VAULT_DIR "${SRC_MAIDSAFE}/vault/*.h")
SET(STYLE_VAULT ${SOURCE_FILES_VAULT_DIR} ${HEADER_FILES_VAULT_DIR})
LIST(REMOVE_ITEM SOURCE_FILES_VAULT_DIR "${SRC_MAIDSAFE}/vault/pdvault_main.cc")
LIST(REMOVE_ITEM SOURCE_FILES_VAULT_DIR "${SRC_MAIDSAFE}/vault/win_service.cc")
LIST(REMOVE_ITEM SOURCE_FILES_VAULT_DIR "${SRC_MAIDSAFE}/vault/unix_deamon.cc")
SET(ALL_FILES_VAULT_DIR ${SOURCE_FILES_VAULT_DIR} ${HEADER_FILES_VAULT_DIR})
SOURCE_GROUP("vault Source Files" FILES ${SOURCE_FILES_VAULT_DIR})
SOURCE_GROUP("vault Header Files" FILES ${HEADER_FILES_VAULT_DIR})

####    TESTS    ####
FILE(GLOB ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/*.cc" "${SRC_MAIDSAFE}/client/tests/*.h")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/client_main.cc")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/testclientcontroller.cc")
LIST(REMOVE_ITEM ALL_FILES_CLIENT_TESTS_DIR "${SRC_MAIDSAFE}/client/tests/testimmessaging.cc")

FILE(GLOB ALL_FILES_CLIENT_FILESYSTEM_TESTS_DIR "${SRC_MAIDSAFE}/client/filesystem/tests/*.cc" "${SRC_MAIDSAFE}/client/filesystem/tests/*.h")

FILE(GLOB ALL_FILES_COMMON_TESTS_DIR "${SRC_MAIDSAFE}/common/tests/*.cc" "${SRC_MAIDSAFE}/common/tests/*.h")
LIST(REMOVE_ITEM ALL_FILES_COMMON_TESTS_DIR "${SRC_MAIDSAFE}/common/tests/testbufferpackethandler.cc")

FILE(GLOB ALL_FILES_FUSE_TESTS_DIR "${SRC_MAIDSAFE}/fuse/tests/*.cc" "${SRC_MAIDSAFE}/fuse/tests/*.h")

FILE(GLOB ALL_FILES_VAULT_TESTS_DIR "${SRC_MAIDSAFE}/vault/tests/*.cc" "${SRC_MAIDSAFE}/vault/tests/*.h")
LIST(REMOVE_ITEM ALL_FILES_VAULT_TESTS_DIR "${SRC_MAIDSAFE}/vault/tests/vault_main.cc")
LIST(REMOVE_ITEM ALL_FILES_VAULT_TESTS_DIR "${SRC_MAIDSAFE}/vault/tests/testpdvault.cc")

SET(NETWORK_TEST_FILES
      "${SRC_MAIDSAFE}/sharedtest/networktest.cc"
      "${SRC_MAIDSAFE}/sharedtest/networktest.h"
      "${SRC_MAIDSAFE}/sharedtest/localvaults.h"
      "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")

###################################################################################################
# All Platforms:  Add exes and Create all PD libs                                                 #
###################################################################################################
IF(APPLE)
  ADD_EXECUTABLE(lifestuff MACOSX_BUNDLE ${ALL_LIFESTUFF_SOURCE_FILES} ${ALL_LIFESTUFF_HEADER_FILES})
  ADD_EXECUTABLE(lslocal MACOSX_BUNDLE ${ALL_LIFESTUFF_SOURCE_FILES} ${ALL_LIFESTUFF_HEADER_FILES})
  ADD_EXECUTABLE(lslightlocal MACOSX_BUNDLE ${ALL_LIFESTUFF_LIGHT_SOURCE_FILES} ${ALL_LIFESTUFF_LIGHT_HEADER_FILES})
  ADD_EXECUTABLE(dedup_analyser MACOSX_BUNDLE ${ALL_DEDUP_ANALYSER_SOURCE_FILES} ${ALL_DEDUP_ANALYSER_HEADER_FILES})
ELSEIF((UNIX AND NOT APPLE) OR MSVC)
  ADD_EXECUTABLE(lifestuff ${ALL_LIFESTUFF_SOURCE_FILES} ${ALL_LIFESTUFF_HEADER_FILES})
  ADD_EXECUTABLE(lslocal ${ALL_LIFESTUFF_SOURCE_FILES} ${ALL_LIFESTUFF_HEADER_FILES})
  ADD_EXECUTABLE(lslightlocal ${ALL_LIFESTUFF_LIGHT_SOURCE_FILES} ${ALL_LIFESTUFF_LIGHT_HEADER_FILES})
  ADD_EXECUTABLE(dedup_analyser ${ALL_DEDUP_ANALYSER_SOURCE_FILES} ${ALL_DEDUP_ANALYSER_HEADER_FILES})
ELSEIF(WIN32)
  ADD_EXECUTABLE(lifestuff WIN32 ${ALL_LIFESTUFF_SOURCE_FILES} ${ALL_LIFESTUFF_HEADER_FILES})
  ADD_EXECUTABLE(lslocal WIN32 ${ALL_LIFESTUFF_SOURCE_FILES} ${ALL_LIFESTUFF_HEADER_FILES})
  ADD_EXECUTABLE(lslightlocal WIN32 ${ALL_LIFESTUFF_LIGHT_SOURCE_FILES} ${ALL_LIFESTUFF_LIGHT_HEADER_FILES})
  ADD_EXECUTABLE(dedup_analyser WIN32 ${ALL_DEDUP_ANALYSER_SOURCE_FILES} ${ALL_DEDUP_ANALYSER_HEADER_FILES})
ENDIF()
IF(MSVC)
  SET_TARGET_PROPERTIES(lifestuff lslocal lslightlocal dedup_analyser PROPERTIES WIN32_EXECUTABLE TRUE)
ENDIF()

SET(BEHAVIOURAL_TEST_TIMEOUT 60)
SET(FUNCTIONAL_TEST_TIMEOUT 600)
SET(LOCAL_SYSTEM_TEST_TIMEOUT 1800)
SET(NETWORK_SYSTEM_TEST_TIMEOUT 3600)

ADD_EXECUTABLE(TESTcommon
                 ${ALL_FILES_COMMON_TESTS_DIR}
                 "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
                 "${SRC_MAIDSAFE}/sharedtest/chunkstoreops.h"
                 "${SRC_MAIDSAFE}/sharedtest/mockkadops.cc"
                 "${SRC_MAIDSAFE}/sharedtest/mockkadops.h"
                 "${SRC_MAIDSAFE}/sharedtest/testcallback.h"
                 "${SRC_MAIDSAFE}/sharedtest/threadpool.cc"
                 "${SRC_MAIDSAFE}/sharedtest/threadpool.h"
                 "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")
ADD_EXECUTABLE(TESTclientfilesystem
                 ${ALL_FILES_CLIENT_FILESYSTEM_TESTS_DIR}
                 "${SRC_MAIDSAFE}/sharedtest/cachepassport.h"
                 "${SRC_MAIDSAFE}/sharedtest/testcallback.h"
                 "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")
ADD_EXECUTABLE(TESTclient
                 ${ALL_FILES_CLIENT_TESTS_DIR}
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
                 "${SRC_MAIDSAFE}/sharedtest/cachepassport.h"
                 "${SRC_MAIDSAFE}/sharedtest/mockkadops.cc"
                 "${SRC_MAIDSAFE}/sharedtest/mockkadops.h"
                 "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
                 "${SRC_MAIDSAFE}/sharedtest/threadpool.cc"
                 "${SRC_MAIDSAFE}/sharedtest/threadpool.h" )

ADD_EXECUTABLE(TESTfuse EXCLUDE_FROM_ALL
                 ${ALL_FILES_FUSE_TESTS_DIR})
ADD_EXECUTABLE(TESTvault
                 ${ALL_FILES_VAULT_TESTS_DIR}
                 "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
                 "${SRC_MAIDSAFE}/sharedtest/chunkstoreops.h"
                 "${SRC_MAIDSAFE}/sharedtest/mockkadops.cc"
                 "${SRC_MAIDSAFE}/sharedtest/mockkadops.h"
                 "${SRC_MAIDSAFE}/sharedtest/threadpool.cc"
                 "${SRC_MAIDSAFE}/sharedtest/threadpool.h"
                 "${SRC_MAIDSAFE}/sharedtest/tests_main.cc")
ADD_EXECUTABLE(TESTauthentication_net
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/client/tests/testauthentication.cc")
ADD_EXECUTABLE(TESTbufferpackethandler_net
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/sharedtest/cached_keys.h"
                 "${SRC_MAIDSAFE}/common/tests/testbufferpackethandler.cc")
ADD_EXECUTABLE(TESTclientcontroller_net
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/sharedtest/mockclientcontroller.h"
                 "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
                 "${SRC_MAIDSAFE}/client/tests/testclientcontroller.cc")
ADD_EXECUTABLE(TESTclientcontroller_local
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/sharedtest/mockclientcontroller.h"
                 "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
                 "${SRC_MAIDSAFE}/client/tests/testclientcontroller.cc")
ADD_EXECUTABLE(TESTimconnectionhandler_net
                 ${NETWORK_TEST_FILES}
                 "${SRC_MAIDSAFE}/client/tests/testimconnhandler.cc"
                 "${SRC_MAIDSAFE}/client/tests/testimmessaging.cc")
ADD_EXECUTABLE(TESTpdvault_net
                 "${SRC_MAIDSAFE}/sharedtest/localvaults.h"
                 "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
                 "${SRC_MAIDSAFE}/sharedtest/networktest.h"
                 "${SRC_MAIDSAFE}/sharedtest/testcallback.h"
                 "${SRC_MAIDSAFE}/vault/tests/testpdvault.cc")

ADD_EXECUTABLE(DEMOclient
                 "${SRC_MAIDSAFE}/client/tests/client_main.cc")
ADD_EXECUTABLE(DEMOvault
                 "${SRC_MAIDSAFE}/sharedtest/mocksessionsingleton.h"
                 "${SRC_MAIDSAFE}/vault/tests/vault_main.cc")
IF(WIN32)
  ADD_EXECUTABLE(vault "${SRC_MAIDSAFE}/vault/win_service.cc")
ELSE()
  ADD_EXECUTABLE(vault "${SRC_MAIDSAFE}/vault/unix_deamon.cc")
ENDIF()

SET(ALL_EXECUTABLES lifestuff lslocal lslightlocal TESTcommon TESTclientfilesystem TESTclient TESTvault TESTauthentication_net TESTbufferpackethandler_net
    TESTclientcontroller_net TESTclientcontroller_local TESTimconnectionhandler_net TESTpdvault_net TESTfuse DEMOclient DEMOvault vault)

ADD_LIBRARY(PDclientlib STATIC ${ALL_FILES_CLIENT_DIR})
ADD_LIBRARY(PDlsmclientlib STATIC ${ALL_FILES_LOCALSTOREMANAGER_CLIENT_DIR})
ADD_LIBRARY(PDclientfilesystemlib STATIC ${ALL_FILES_CLIENT_FILESYSTEM_DIR})
ADD_LIBRARY(PDcommonlib STATIC ${ALL_FILES_COMMON_DIR})
ADD_LIBRARY(PDfuselib STATIC ${ALL_FILES_FUSE_DIR})
ADD_LIBRARY(PDvaultlib STATIC ${ALL_FILES_VAULT_DIR})

ADD_SUBDIRECTORY(${SRC_MAIDSAFE}/encrypt ${CMAKE_BINARY_DIR}/encrypt)
ADD_SUBDIRECTORY(${SRC_MAIDSAFE}/passport ${CMAKE_BINARY_DIR}/passport)
ADD_SUBDIRECTORY(${SRC_MAIDSAFE}/pki ${CMAKE_BINARY_DIR}/pki)

# Force renaming of exes to match standard CMake library renaming policy
IF(NOT MSVC)
  FOREACH(EXECUTABLE ${ALL_EXECUTABLES})
    SET_TARGET_PROPERTIES(${EXECUTABLE} PROPERTIES
                            DEBUG_OUTPUT_NAME ${EXECUTABLE}${CMAKE_DEBUG_POSTFIX}
                            RELWITHDEBINFO_OUTPUT_NAME ${EXECUTABLE}${CMAKE_RELWITHDEBINFO_POSTFIX}
                            MINSIZEREL_OUTPUT_NAME ${EXECUTABLE}${CMAKE_MINSIZEREL_POSTFIX})
  ENDFOREACH()
ENDIF()

# When this target is built, it removes all .gcda files from the build directory and its subdirectories
IF(UNIX)
  ADD_CUSTOM_TARGET(CleanCoverage COMMAND ${CMAKE_COMMAND} -DSEARCH_DIR=${CMAKE_BINARY_DIR} -P ${${PROJECT_NAME}_ROOT}/build/clean_coverage.cmake)
ENDIF()
ADD_CUSTOM_TARGET(AllTestsAndDemos DEPENDS TESTencrypt TESTpassport TESTpki TESTcommon TESTclientfilesystem TESTclient TESTvault TESTfuse TESTauthentication_net
                    TESTbufferpackethandler_net TESTclientcontroller_net TESTclientcontroller_local TESTimconnectionhandler_net TESTpdvault_net DEMOclient DEMOvault
                    dedup_analyser)
SET(TEST_EXECUTABLES )


###################################################################################################
# Builds                                                                                          #
###################################################################################################
ADD_DEFINITIONS(-DSTATICLIB)
SET(BUILD_SHARED_LIBS OFF)

TARGET_LINK_LIBRARIES(PDcommonlib passport ${Boost_FILESYSTEM_LIBRARY})
TARGET_LINK_LIBRARIES(PDclientfilesystemlib PDcommonlib encrypt pki ${Boost_DATE_TIME_LIBRARY})
TARGET_LINK_LIBRARIES(PDlsmclientlib PDclientfilesystemlib ${QT_LIBRARIES} ${Boost_REGEX_LIBRARY})
TARGET_LINK_LIBRARIES(PDclientlib PDclientfilesystemlib ${QT_LIBRARIES} ${Boost_REGEX_LIBRARY})
TARGET_LINK_LIBRARIES(PDvaultlib PDcommonlib pki ${QT_LIBRARIES} ${Boost_DATE_TIME_LIBRARY})
TARGET_LINK_LIBRARIES(PDfuselib ${Fuse_LIBRARY} ${Boost_SYSTEM_LIBRARY})
TARGET_LINK_LIBRARIES(lifestuff PDclientlib PDfuselib ${QT_LIBRARIES})
TARGET_LINK_LIBRARIES(lslocal PDlsmclientlib PDfuselib ${QT_LIBRARIES})
TARGET_LINK_LIBRARIES(lslightlocal PDlsmclientlib ${QT_LIBRARIES})
TARGET_LINK_LIBRARIES(TESTcommon PDcommonlib ${Boost_DATE_TIME_LIBRARY} ${Gtest_LIBRARY} ${Gmock_LIBRARY})
TARGET_LINK_LIBRARIES(TESTclientfilesystem PDclientlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTclient PDclientlib PDvaultlib ${Gtest_LIBRARY} ${Gmock_LIBRARY})
TARGET_LINK_LIBRARIES(TESTvault PDvaultlib PDclientlib ${Gtest_LIBRARY} ${Gmock_LIBRARY})
TARGET_LINK_LIBRARIES(TESTfuse PDfuselib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTauthentication_net PDclientlib PDvaultlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTbufferpackethandler_net PDclientlib PDvaultlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTclientcontroller_net PDclientlib PDvaultlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTclientcontroller_local PDlsmclientlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTimconnectionhandler_net PDclientlib PDvaultlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTpdvault_net PDclientlib PDvaultlib ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(DEMOclient PDclientlib)
TARGET_LINK_LIBRARIES(DEMOvault PDclientlib PDvaultlib)
TARGET_LINK_LIBRARIES(vault PDvaultlib)
TARGET_LINK_LIBRARIES(dedup_analyser ${QT_LIBRARIES} maidsafe_dht_LIBRARY)

###################################################################################################
# Compiler and linker flags - after all targets declared                                          #
###################################################################################################
IF(Glog_FOUND)
  ADD_DEFINITIONS(-DHAVE_GLOG)
ENDIF()
ADD_DEFINITIONS(-DBOOST_FILESYSTEM_NO_DEPRECATED -DBOOST_FILESYSTEM_VERSION=3)

SET_TARGET_PROPERTIES(PDlsmclientlib PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)
SET_TARGET_PROPERTIES(TESTauthentication_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
SET_TARGET_PROPERTIES(TESTbufferpackethandler_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
SET_TARGET_PROPERTIES(TESTclientcontroller_local PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)
SET_TARGET_PROPERTIES(TESTclientcontroller_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
SET_TARGET_PROPERTIES(TESTimconnectionhandler_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
SET_TARGET_PROPERTIES(TESTpdvault_net PROPERTIES COMPILE_FLAGS -DMS_NETWORK_TEST)
SET_TARGET_PROPERTIES(lslightlocal PROPERTIES COMPILE_FLAGS "-DPD_LIGHT -DLOCAL_PDVAULT")
IF(APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPD_APPLE -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DQT_NO_DEBUG_OUTPUT -DQT_NO_WARNING_OUTPUT -DQT_NO_DEBUG_STREAM -O2 -Wuninitialized")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
  SET_TARGET_PROPERTIES(lifestuff lslocal PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)
ELSEIF(UNIX AND NOT APPLE)
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -DDEBUG -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DQT_NO_DEBUG_OUTPUT -DQT_NO_WARNING_OUTPUT -DQT_NO_DEBUG_STREAM -O2 -Wuninitialized")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra -Wall -DPD_LINUX -DPD_POSIX -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -Wredundant-decls -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -ansi -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  SET_TARGET_PROPERTIES(lifestuff lslocal PROPERTIES COMPILE_FLAGS "-w -DLOCAL_PDVAULT")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
ELSEIF(WIN32)
  ADD_DEFINITIONS(-DPD_WIN32 -DWIN32 -D_WIN32 -D__WINDOWS__ -D__WIN32__ -D_WINDOWS)
  ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x501)
  ADD_DEFINITIONS(-D_UNICODE -DUNICODE -D_BIND_TO_CURRENT_VCLIBS_VERSION=1)
  IF(MSVC)
    # flag to link to static version of Google Glog
    IF(Glog_FOUND)
      ADD_DEFINITIONS(-DGOOGLE_GLOG_DLL_DECL=)
    ENDIF()
    ADD_DEFINITIONS(-D__MSVC__ -DNOMINMAX -DBOOST_ALL_NO_LIB -DUDT_STATIC)
    SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Ot /Oy /GL /D \"NDEBUG\" /EHsc /MD /Gy /W3 /Zi /wd4503 /D \"QT_NO_DEBUG_OUTPUT\" /D \"QT_NO_WARNING_OUTPUT\" /D \"QT_NO_DEBUG_STREAM\"")
    SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D \"_DEBUG\" /D \"DEBUG\" /EHsc /MDd  /c /ZI /TP /wd4503")
    # CMake defaults to passing stack size in LINKER_FLAGS of 10MB.  Set this to windows default of 1MB
    STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
    # Given a link dir of "a/b/c", MSVC adds "a/b/c/" AND "a/b/c/CMAKE_BUILD_TYPE" as link dirs, so we
    # can't just use "LINK_DIRECTORIES" as some Google debug libs have the same name as the release version.
    FOREACH(LIBS_DIR ${LIBS_DIRS})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
      SET(LINKER_LIBS_DIRS_RELEASE "${LINKER_LIBS_DIRS_RELEASE} /LIBPATH:\"${LIBS_DIR}\"")
    ENDFOREACH()
    FOREACH(LIBS_DIR_DEBUG ${LIBS_DIRS_DEBUG})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR_DEBUG ${LIBS_DIR_DEBUG})
      SET(LINKER_LIBS_DIRS_DEBUG "${LINKER_LIBS_DIRS_DEBUG} /LIBPATH:\"${LIBS_DIR_DEBUG}\"")
    ENDFOREACH()
    SET_TARGET_PROPERTIES(${ALL_EXECUTABLES} PROPERTIES
                              LINK_FLAGS "/STACK:1048576"
                              LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                              LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                              LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                              LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
    SET_TARGET_PROPERTIES(lifestuff lslocal PROPERTIES COMPILE_FLAGS "-DLOCAL_PDVAULT")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG") # -g -pg -fprofile-arcs -ftest-coverage")
    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DQT_NO_DEBUG_OUTPUT -DQT_NO_WARNING_OUTPUT -DQT_NO_DEBUG_STREAM -O2 -Wuninitialized")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I c:/usr/include -D_FORTIFY_SOURCE=2 -D__MINGW__ -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static -mthreads -D_GLIBCXX_USE_WCHAR_T")
    # SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--enable-auto-import")
    # SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
    SET_TARGET_PROPERTIES(lifestuff lslocal PROPERTIES COMPILE_FLAGS "-w -DLOCAL_PDVAULT")
  ENDIF()
ENDIF()

###################################################################################################
# Tests                                                                                           #
###################################################################################################
INCLUDE(CTest)
SET(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CUSTOM_MAXIMUM_FAILED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CONTINUOUS_DURATION 600)
SET(CTEST_CONTINUOUS_MINIMUM_INTERVAL 60)
SET(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)

IF(EXCLUDE_TEST)
  SET(EXCLUDED_TESTS ${EXCLUDED_TESTS} ${EXCLUDE_TEST})
  LIST(REMOVE_DUPLICATES EXCLUDED_TESTS)
  SET(EXCLUDED_TESTS ${EXCLUDED_TESTS} CACHE INTERNAL "List of tests to exclude from CTest" FORCE)
  UNSET(EXCLUDE_TEST CACHE)
ENDIF()

IF(INCLUDE_TEST)
  IF(EXCLUDED_TESTS)
    LIST(REMOVE_DUPLICATES EXCLUDED_TESTS)
    LIST(REMOVE_ITEM EXCLUDED_TESTS ${INCLUDE_TEST})
  ENDIF()
  SET(EXCLUDED_TESTS ${EXCLUDED_TESTS} CACHE INTERNAL "List of tests to exclude from CTest" FORCE)
  UNSET(INCLUDE_TEST CACHE)
ENDIF()

FUNCTION(GET_TEST_PARAMETERS GTEST_SOURCE_FILE GTEST_GROUP_NAME)
  # Find start of parameter list
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_PARAMETER_CASE REGEX ^INSTANTIATE_TEST_CASE_P.*${GTEST_GROUP_NAME},)
  IF(NOT GTEST_PARAMETER_CASE)
    RETURN()
  ENDIF()
  # Get instantiation name
  STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_PARAMETER_CASE_AS_LIST ${GTEST_PARAMETER_CASE})
  LIST(GET GTEST_PARAMETER_CASE_AS_LIST 1 GTEST_INSTANTIATION_NAME)
  # Read file into variable FULL_FILE
  FILE(STRINGS ${GTEST_SOURCE_FILE} FULL_FILE REGEX .)
  # Get line number of start of parameter list
  LIST(FIND FULL_FILE ${GTEST_PARAMETER_CASE} PARAMETER_VALUES_INDEX)
  # Use comma count to add appendices to list until closing bracket is found
  SET(PARAMETER_COUNT 0)
  WHILE(NOT END_OF_PARAM_LIST)
    LIST(GET FULL_FILE ${PARAMETER_VALUES_INDEX} GTEST_PARAMS)
    STRING(REGEX MATCHALL [,] COMMA_LIST ${GTEST_PARAMS})
    FOREACH(COMMA ${COMMA_LIST})
      SET(GTEST_PARAMETER_APPENDICES ${GTEST_PARAMETER_APPENDICES} "/${PARAMETER_COUNT}")
      MATH(EXPR PARAMETER_COUNT ${PARAMETER_COUNT}+1)
    ENDFOREACH()
    STRING(REGEX MATCH [\)] END_OF_PARAM_LIST ${GTEST_PARAMS})
    MATH(EXPR PARAMETER_VALUES_INDEX ${PARAMETER_VALUES_INDEX}+1)
  ENDWHILE()
  IF(NOT PARAMETER_COUNT EQUAL 0)
    LIST(REMOVE_AT GTEST_PARAMETER_APPENDICES -1)
  ENDIF()
  SET(GTEST_INSTANTIATION_NAME ${GTEST_INSTANTIATION_NAME}/ PARENT_SCOPE)
  SET(GTEST_PARAMETER_APPENDICES ${GTEST_PARAMETER_APPENDICES} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(GET_TEST_TYPES GTEST_SOURCE_FILE GTEST_GROUP_NAME)
  # Find TYPED_TEST_CASE and retrieve associated typedef
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_TYPED_TEST_CASE REGEX ^TYPED_TEST_CASE)
  IF(NOT GTEST_TYPED_TEST_CASE)
    RETURN()
  ENDIF()
  STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_TYPED_TEST_CASE ${GTEST_TYPED_TEST_CASE})
  LIST(GET GTEST_TYPED_TEST_CASE 3 GTEST_TYPEDEF)
  # Get type list from typedef
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_TYPES REGEX ">\ ${GTEST_TYPEDEF}")
  # Read file into variable FULL_FILE
  FILE(STRINGS ${GTEST_SOURCE_FILE} FULL_FILE REGEX .)
  # Get line number of end of type list
  LIST(FIND FULL_FILE ${GTEST_TYPES} PARAMETER_VALUES_INDEX)
  # Use comma count to add appendices to list until opening bracket is found
  SET(PARAMETER_COUNT 0)
  SET(GTEST_TYPE_APPENDICES ${GTEST_TYPE_APPENDICES} "/${PARAMETER_COUNT}")
  WHILE(NOT START_OF_TYPE_LIST)
    LIST(GET FULL_FILE ${PARAMETER_VALUES_INDEX} GTEST_PARAMS)
    STRING(REGEX MATCHALL [,] COMMA_LIST ${GTEST_PARAMS})
    FOREACH(COMMA ${COMMA_LIST})
      MATH(EXPR PARAMETER_COUNT ${PARAMETER_COUNT}+1)
      SET(GTEST_TYPE_APPENDICES ${GTEST_TYPE_APPENDICES} "/${PARAMETER_COUNT}")
    ENDFOREACH()
    STRING(REGEX MATCH [<] START_OF_TYPE_LIST ${GTEST_PARAMS})
    MATH(EXPR PARAMETER_VALUES_INDEX ${PARAMETER_VALUES_INDEX}-1)
  ENDWHILE()
  SET(GTEST_TYPE_APPENDICES ${GTEST_TYPE_APPENDICES} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(ADD_MAIDSAFE_TEST GTEST_GROUP_NAME GTEST_NAME TEST_PATH)
  ADD_TEST(${GTEST_GROUP_NAME}.${GTEST_NAME} ${TEST_PATH} --gtest_filter=${GTEST_GROUP_NAME}.${GTEST_NAME})
  IF("${GTEST_NAME}" MATCHES "^FUNC_" OR "${GTEST_NAME}" MATCHES "^DISABLED_FUNC_")
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY LABELS Functional ${GTEST_GROUP_NAME})
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY TIMEOUT 600)
  ELSEIF("${GTEST_NAME}" MATCHES "^BEH_" OR "${GTEST_NAME}" MATCHES "^DISABLED_BEH_")
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY LABELS Behavioural ${GTEST_GROUP_NAME})
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY TIMEOUT 60)
  ELSE()
    MESSAGE("")
    MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    MESSAGE("")
    MESSAGE(AUTHOR_WARNING "${GTEST_NAME} should be named \"BEH_...\" or \"FUNC_...\" (with an optional \"DISABLED_\" prepended).")
    MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
  ENDIF()
ENDFUNCTION()

SET(TEST_EXECUTABLES TESTclient TESTclientfilesystem TESTcommon TESTvault TESTencrypt TESTpassport TESTpki TESTfuse)
FOREACH(TEST_EXECUTABLE ${TEST_EXECUTABLES})
  IF(TEST_EXECUTABLE STREQUAL "TESTclient")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_CLIENT_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTclientfilesystem")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_CLIENT_FILESYSTEM_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTcommon")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_COMMON_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTvault")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_VAULT_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTencrypt")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_ENCRYPT_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTpassport")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_PASSPORT_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTpki")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_PKI_TESTS_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTfuse")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_FUSE_TESTS_DIR})
  ENDIF()
  FOREACH(GTEST_SOURCE_FILE ${GTEST_SOURCE_FILES})
    FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_NAMES REGEX ^TEST)
    FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_TYPED_NAMES REGEX ^TYPED_TEST)
    SET(GTEST_NAMES ${GTEST_NAMES} ${GTEST_TYPED_NAMES})
    FOREACH(GTEST_NAME ${GTEST_NAMES})
      STRING(REGEX MATCH "TEST_MS_NET" TEST_IS_MS_NETWORK_TYPE ${GTEST_NAME})
      STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_NAME ${GTEST_NAME})
      LIST(GET GTEST_NAME 0 GTEST_TEST_TYPE)
      LIST(GET GTEST_NAME 1 GTEST_GROUP_NAME)
      IF(TEST_IS_MS_NETWORK_TYPE)
        LIST(GET GTEST_NAME 3 GTEST_NAME_PART1)
        LIST(GET GTEST_NAME 5 GTEST_NAME_PART2)
        LIST(GET GTEST_NAME 7 GTEST_NAME_PART3)
        SET(GTEST_NAME "${GTEST_NAME_PART1}_${GTEST_NAME_PART2}_${GTEST_NAME_PART3}")
      ELSE()
        LIST(GET GTEST_NAME 3 GTEST_NAME)
      ENDIF()
      LIST(FIND EXCLUDED_TESTS ${GTEST_GROUP_NAME}.${GTEST_NAME} THIS_GTEST_EXCLUDED)
      IF(THIS_GTEST_EXCLUDED EQUAL -1)
        IF("${GTEST_NAME}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
          IF(${GTEST_TEST_TYPE} MATCHES TEST_P)
            SET(GTEST_PARAMETER_APPENDICES)
            SET(GTEST_INSTANTIATION_NAME)
            GET_TEST_PARAMETERS(${GTEST_SOURCE_FILE} ${GTEST_GROUP_NAME})
            FOREACH(GTEST_PARAMETER_APPENDIX ${GTEST_PARAMETER_APPENDICES})
              ADD_MAIDSAFE_TEST(${GTEST_INSTANTIATION_NAME}${GTEST_GROUP_NAME} ${GTEST_NAME}${GTEST_PARAMETER_APPENDIX} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX})
            ENDFOREACH()
          ELSEIF(${GTEST_TEST_TYPE} MATCHES TYPED_TEST)
            SET(GTEST_TYPE_APPENDICES)
            GET_TEST_TYPES(${GTEST_SOURCE_FILE} ${GTEST_GROUP_NAME})
            FOREACH(GTEST_TYPE_APPENDIX ${GTEST_TYPE_APPENDICES})
              ADD_MAIDSAFE_TEST(${GTEST_GROUP_NAME}${GTEST_TYPE_APPENDIX} ${GTEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX})
            ENDFOREACH()
          ELSE()
            ADD_MAIDSAFE_TEST(${GTEST_GROUP_NAME} ${GTEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX})
          ENDIF()
        ENDIF()
      ENDIF()
    ENDFOREACH()
  ENDFOREACH()
ENDFOREACH()

IF(NOT ${MAIDSAFE_TEST_TYPE} MATCHES "BEH")
  LIST(FIND EXCLUDED_TESTS Test_authentication_net TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Test_authentication_net ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTauthentication_net${TEST_POSTFIX})
    SET_PROPERTY(TEST Test_authentication_net PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Test_authentication_net PROPERTY LABELS Functional Authentication)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Test_bufferpackethandler_net TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Test_bufferpackethandler_net ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTbufferpackethandler_net${TEST_POSTFIX})
    SET_PROPERTY(TEST Test_bufferpackethandler_net PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Test_bufferpackethandler_net PROPERTY LABELS Functional BufferPacketHandler)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Test_clientcontroller_net TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Test_clientcontroller_net ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTclientcontroller_net${TEST_POSTFIX})
    SET_PROPERTY(TEST Test_clientcontroller_net PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Test_clientcontroller_net PROPERTY LABELS Functional ClientController NetworkCC)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Test_clientcontroller_local TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Test_clientcontroller_local ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTclientcontroller_local${TEST_POSTFIX})
    SET_PROPERTY(TEST Test_clientcontroller_local PROPERTY TIMEOUT ${LOCAL_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Test_clientcontroller_local PROPERTY LABELS Functional ClientController LocalCC)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Test_imconnectionhandler_net TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Test_imconnectionhandler_net ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTimconnectionhandler_net${TEST_POSTFIX})
    SET_PROPERTY(TEST Test_imconnectionhandler_net PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Test_imconnectionhandler_net PROPERTY LABELS Functional InstantMessaging)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Test_pdvault_net TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Test_pdvault_net ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTpdvault_net${TEST_POSTFIX})
    SET_PROPERTY(TEST Test_pdvault_net PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Test_pdvault_net PROPERTY LABELS Functional PdVault)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS STYLE_CHECK TEST_EXCLUDED)
  IF((TEST_EXCLUDED EQUAL -1) AND PYTHONINTERP_FOUND)
    IF(UNIX)
      SET(STYLE_ALL ${STYLE_CLIENT} ${STYLE_COMMON} ${STYLE_DEDUP_ANALYSER} ${STYLE_FUSE}
            ${STYLE_VAULT} ${STYLE_ENCRYPT} ${STYLE_PASSPORT} ${STYLE_PKI})
      ADD_TEST(STYLE_CHECK ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${STYLE_ALL})
      SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
    ELSE()
      ADD_TEST(STYLE_CHECK ${${PROJECT_NAME}_ROOT}/build/tools/finderrorsall.bat)
      SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
    ENDIF()
  ENDIF()
ENDIF()

IF(UNIX)
  SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF(UNIX)

###################################################################################################
# Adding the install targets                                                                      #
###################################################################################################
MESSAGE("")
MESSAGE("${MAIDSAFE_TEST_TYPE_MESSAGE}")
MESSAGE("")
MESSAGE("    To include all tests,                ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=ALL")
MESSAGE("    To include behavioural tests,        ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE("    To include functional tests,        ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE("================================================================================")
MESSAGE("")
IF(EXCLUDED_TESTS)
  MESSAGE("Tests excluded:")
  FOREACH(EXCLUDED_TEST ${EXCLUDED_TESTS})
    MESSAGE("-- ${EXCLUDED_TEST}")
  ENDFOREACH()
ELSE()
  MESSAGE("No tests excluded.")
ENDIF()
MESSAGE("")
MESSAGE("    To exclude a test,                 ${ERROR_MESSAGE_CMAKE_PATH} -DEXCLUDE_TEST=<Test Name>")
MESSAGE("    To re-include a test,              ${ERROR_MESSAGE_CMAKE_PATH} -DINCLUDE_TEST=<Test Name>")
MESSAGE("================================================================================")
MESSAGE("")
IF(NOT MSVC)
  MESSAGE("Build type is set to \"${CMAKE_BUILD_TYPE}\"")
  IF((NOT MAIDSAFE_DHT_BUILD_TYPE MATCHES "Debug") AND
     (NOT MAIDSAFE_DHT_BUILD_TYPE MATCHES "RelWithDebInfo") AND
     (NOT MAIDSAFE_DHT_BUILD_TYPE MATCHES "MinSizeRel"))
    SET(MAIDSAFE_DHT_BUILD_TYPE Release)
  ENDIF()
  MESSAGE("Linking to \"${MAIDSAFE_DHT_BUILD_TYPE}\" build of maidsafe-dht, cryptopp & udt")
  MESSAGE("")
  MESSAGE("    To alter build type (e.g. to Debug), ${ERROR_MESSAGE_CMAKE_PATH} -DCMAKE_BUILD_TYPE=Debug")
  MESSAGE("")
  MESSAGE("    To link to (e.g. Debug) build of maidsafe-dht, cryptopp & udt,")
  MESSAGE("                                  ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_BUILD_TYPE=Debug")
  MESSAGE("")
  MESSAGE("    Options are Release, Debug, RelWithDebInfo, MinSizeRel")
  MESSAGE("================================================================================")
  MESSAGE("")
ENDIF()


# BitRock InstallBuilder
IF(CMAKE_BUILD_TYPE MATCHES Release)
  INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindInstallBuilder.cmake)
  IF(InstallBuilder_BUILDER_EXE AND InstallBuilder_CUSTOMISE_EXE)
    ADD_CUSTOM_TARGET(lifestuffInstaller ALL ${InstallBuilder_BUILDER_EXE} build ${${PROJECT_NAME}_ROOT}/installer/bitrock/lifestuff.xml DEPENDS lifestuff vault)
    ADD_CUSTOM_TARGET(lslightlocalInstaller ALL ${InstallBuilder_BUILDER_EXE} build ${${PROJECT_NAME}_ROOT}/installer/bitrock/lslightlocal.xml DEPENDS lslightlocal)
  ENDIF()
ENDIF()
