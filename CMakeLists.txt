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


PROJECT(PD)
MESSAGE("================================================================================\n")
SET(CMAKE_CACHEFILE "${CMAKE_CACHEFILE_DIR}/CMakeCache.txt")
IF(WIN32)
  STRING(REPLACE "/" "\\" CMAKE_CACHEFILE ${CMAKE_CACHEFILE})
ENDIF()
SET(ERROR_MESSAGE "No generator previously specified.  Run:\n")
IF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\tcmake ../.. -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\tcmake ../.. -G\"CodeBlocks - MinGW Makefiles\"\n\n")
ENDIF(UNIX)
SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\tcmake ../.. --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

FIND_PROGRAM(GITCOMMAND git PATHS ENV ProgramFiles PATH_SUFFIXES "Git/bin")
SET(UPDATE_TYPE git)
SET(UPDATE_COMMAND "${GITCOMMAND}")

IF(MSVC)
  SET(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "The type of build." FORCE)
ELSEIF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF()
IF(NOT MAIDSAFE_TEST_TYPE)
  SET(MAIDSAFE_TEST_TYPE "BEH" CACHE INTERNAL "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF()

OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)

IF(UNIX)
  EXECUTE_PROCESS(COMMAND date +%a%d%m%y OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
ELSE()
  EXECUTE_PROCESS(COMMAND CMD /C DATE /T OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
  STRING(REPLACE "/" "" pddate ${pddate})
  STRING(SUBSTRING ${pddate} 0 4 pddateddmm)
  STRING(SUBSTRING ${pddate} 6 2 pddateyy)
  SET(pddate ${pddateddmm}${pddateyy})
ENDIF()

IF(APPLE)
  SET(CMAKE_OSX_SYSROOT "/")
ENDIF(APPLE)
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${PD_BINARY_DIR} NAME)

UNSET(CMAKE_RUNTIME_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_LIBRARY_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY CACHE)
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/x64 CACHE PATH "Executable target dir (x64).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/x64 CACHE PATH "Shared library target dir (x64).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/x64 CACHE PATH "Static library target dir (x64).")
  ELSE()
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/win32 CACHE PATH "Executable target dir (win32).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/win32 CACHE PATH "Shared library target dir (win32).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/win32 CACHE PATH "Static library target dir (win32).")
  ENDIF()
ELSE()
  MESSAGE("Building a package which is OK to release.")
  MESSAGE("------------------------------------------")
  SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin CACHE PATH "Executable target dir.")
  SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin CACHE PATH "Shared library target dir.")
  SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin CACHE PATH "Static library target dir.")
ENDIF()

IF((NOT MSVC) AND NOT (${CMAKE_BUILD_TYPE_DIR} MATCHES "kdev"))
  IF(CMAKE_BUILD_TYPE MATCHES "Release")
    MESSAGE("Building a package which is OK to release.")
  ELSE()
    MESSAGE("Building a package which is NOT OK to release.")
    SET(pddate "DEVELOPER_${pddate}")
  ENDIF()
  MESSAGE("----------------------------------------------")
ENDIF()

SET(CMAKE_DEBUG_POSTFIX _d)
SET(CMAKE_RELWITHDEBINFO_POSTFIX _rwdi)
SET(CMAKE_MINSIZEREL_POSTFIX _msr)

###################################################################################################
# Set default directories to be searched for included files and libs                              #
###################################################################################################
SET(SOURCE_DIR ${PD_SOURCE_DIR}/src)

IF(DEFINED ADD_LIBRARY_DIR)
  IF(DEFAULT_LIBRARY_DIR)
    LIST(REMOVE_DUPLICATES DEFAULT_LIBRARY_DIR)
  ENDIF()
  SET(DEFAULT_LIBRARY_DIR ${DEFAULT_LIBRARY_DIR} ${ADD_LIBRARY_DIR} CACHE INTERNAL "Path to libraries directories" FORCE)
ENDIF()

IF(MSVC)
  SET(CMAKE_INCLUDE_PATH "c:\\msvc\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\msvc\\lib" ${DEFAULT_LIBRARY_DIR})
ELSEIF(WIN32)
  SET(CMAKE_INCLUDE_PATH "c:\\usr\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\usr\\lib" ${DEFAULT_LIBRARY_DIR})
ELSE()
  SET(CMAKE_INCLUDE_PATH "/usr/include")
  SET(CMAKE_LIBRARY_PATH "/usr/lib" ${DEFAULT_LIBRARY_DIR})
ENDIF()
IF(MINGW)
  SET(CMAKE_INCLUDE_PATH "c:\\MinGW\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\MinGW\\lib" ${DEFAULT_LIBRARY_DIR})
ENDIF(MINGW)

###################################################################################################
# Boost libraries search                                                                          #
###################################################################################################
SET(REQUIRED_BOOST_COMPONENTS date_time filesystem regex system thread)
INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindBoost.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Boost_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Boost_LIBRARY_DIRS})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Boost_LIBRARY_DIRS})

###################################################################################################
# QT library search                                                                               #
###################################################################################################
# Including this file sets up environment with correct dirs / flags - no need to explicitly set
# anything else other than linking to QT_LIBRARIES as appropriate.
INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindQt4.cmake)

###################################################################################################
# Google Test library search                                                                      #
###################################################################################################
INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindGtest.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gtest_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gtest_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Gtest_LIBRARY_DIR_DEBUG})

###################################################################################################
# Google Mock library search                                                                      #
###################################################################################################
INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindGmock.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gmock_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gmock_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Gmock_LIBRARY_DIR_DEBUG})

###################################################################################################
# Google Log library search - Glog can't currently be compiled on Windows with MinGW              #
###################################################################################################
IF((NOT WIN32) OR MSVC)
  INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindGlog.cmake)
  IF(Glog_FOUND)
    SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Glog_INCLUDE_DIR})
    SET(LIBS_DIRS ${LIBS_DIRS} ${Glog_LIBRARY_DIR} ${Glog_LIBRARY_DIR_DEBUG})
  ENDIF()
ENDIF()

###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB PROTO_FILES RELATIVE ${SOURCE_DIR} "${SOURCE_DIR}/protobuf/*.proto")
INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindProtobuf.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Protobuf_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Protobuf_LIBRARY_DIR_DEBUG})

###################################################################################################
# Google BreakPad library search                                                                  #
###################################################################################################
IF((UNIX AND NOT APPLE) OR MSVC)
  INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindBreakpad.cmake)
  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Breakpad_INCLUDE_DIR})
  SET(LIBS_DIRS ${LIBS_DIRS} ${Breakpad_LIBRARY_DIR})
  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Breakpad_LIBRARY_DIR_DEBUG})
ENDIF()

###################################################################################################
# Python library search                                                                           #
###################################################################################################
UNSET(PYTHON_EXECUTABLE CACHE)
INCLUDE(FindPythonInterp)
FIND_PACKAGE(PythonInterp)
IF(PYTHONINTERP_FOUND)
  MESSAGE("-- Found python executable: style checking enabled.")
ELSE(PYTHONINTERP_FOUND)
  MESSAGE("-- Didn't find python executable: style checking disabled.")
ENDIF(PYTHONINTERP_FOUND)

###################################################################################################
# maidsafe-dht, cryptopp and udt library search                                                   #
###################################################################################################
INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindMaidsafeDht.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${maidsafe_dht_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${maidsafe_dht_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${maidsafe_dht_LIBRARY_DIR_DEBUG})

###################################################################################################
# Dokan library search                                                                            #
###################################################################################################
IF(WIN32)
  INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindDokan.cmake)
  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Dokan_INCLUDE_DIR})
  SET(LIBS_DIRS ${LIBS_DIRS} ${Dokan_LIBRARY_DIR})
  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Dokan_LIBRARY_DIR})
ENDIF()

###################################################################################################
# All other libraries search                                                                      #
###################################################################################################
IF(UNIX)
  SET(SYS_LIBS  libfuse.a)
  IF(NOT APPLE)
    SET(SYS_LIBS rt c ${SYS_LIBS})
  ENDIF()
ELSEIF(WIN32)
  IF(MSVC)
    SET(SYS_LIBS ws2_32 odbc32 odbccp32 WSock32 IPHlpApi)
  ELSE()
    SET(SYS_LIBS advapi32 ws2_32 iphlpapi mswsock)
  ENDIF()
ENDIF()
FOREACH(library ${SYS_LIBS})
  FIND_LIBRARY(CURRENT_LIB ${library})
  IF(CURRENT_LIB)
    MESSAGE("-- Found library ${CURRENT_LIB}")
    GET_FILENAME_COMPONENT(CURRENT_LIBRARY_DIR ${CURRENT_LIB} PATH)
    SET(LIBS_DIRS ${LIBS_DIRS} ${CURRENT_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${CURRENT_LIBRARY_DIR})
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find library ${library}.  Run\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DADD_LIBRARY_DIR=<Path to ${library} directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  UNSET(CURRENT_LIB CACHE)
ENDFOREACH()

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
FILE(GLOB M_QT_C "${SOURCE_DIR}/qt/*.c*")
FILE(GLOB M_QT_H "${SOURCE_DIR}/qt/*.h*")
FILE(GLOB M_QT_WIDGETS_C "${SOURCE_DIR}/qt/widgets/*.c*")
FILE(GLOB M_QT_WIDGETS_H "${SOURCE_DIR}/qt/widgets/*.h*")
FILE(GLOB M_QT_CLIENT_C "${SOURCE_DIR}/qt/client/*.c*")
FILE(GLOB M_QT_CLIENT_H "${SOURCE_DIR}/qt/client/*.h*")
FILE(GLOB M_QT_UI "${SOURCE_DIR}/qt/ui/*.ui")
FILE(GLOB M_QT_QRC "${SOURCE_DIR}/qt/resources/*.qrc")
LIST(APPEND M_QT_C ${M_QT_WIDGETS_C} ${M_QT_CLIENT_C})
LIST(APPEND M_QT_H ${M_QT_WIDGETS_H} ${M_QT_CLIENT_H})
SET(M_QT_FB_C ${M_QT_C})
SET(M_QT_FB_H ${M_QT_H})
LIST(REMOVE_ITEM M_QT_C "${SOURCE_DIR}/qt/widgets/file_browser.cc")
LIST(REMOVE_ITEM M_QT_H "${SOURCE_DIR}/qt/widgets/file_browser.h")
LIST(APPEND M_QT_DIR ${M_QT_FB_C} ${M_QT_FB_H})
FILE(GLOB M_PROTOBUF_C "${SOURCE_DIR}/protobuf/*.c*")
FILE(GLOB M_PROTOBUF_H "${SOURCE_DIR}/protobuf/*.h*")
LIST(APPEND M_PROTOBUF_DIR ${M_PROTOBUF_C} ${M_PROTOBUF_H})
FILE(GLOB M_MAIDSAFE_C "${SOURCE_DIR}/maidsafe/*.c*")
FILE(GLOB M_MAIDSAFE_H "${SOURCE_DIR}/maidsafe/*.h*")
LIST(APPEND M_MAIDSAFE_DIR ${M_MAIDSAFE_C} ${M_MAIDSAFE_H})
LIST(APPEND STYLE_MAIDSAFE ${M_MAIDSAFE_C} ${M_MAIDSAFE_H})
FILE(GLOB M_MSCLIENT_C "${SOURCE_DIR}/maidsafe/client/*.c*")
FILE(GLOB M_MSCLIENT_H "${SOURCE_DIR}/maidsafe/client/*.h*")
LIST(APPEND M_MSCLIENT_DIR ${M_MSCLIENT_C} ${M_MSCLIENT_H})
LIST(APPEND STYLE_MSCLIENT ${M_MSCLIENT_C} ${M_MSCLIENT_H})
FILE(GLOB M_MSVAULT_C "${SOURCE_DIR}/maidsafe/vault/*.c*")
FILE(GLOB M_MSVAULT_H "${SOURCE_DIR}/maidsafe/vault/*.h*")
LIST(APPEND M_MSVAULT_DIR ${M_MSVAULT_C} ${M_MSVAULT_H})
LIST(REMOVE_ITEM M_MSVAULT_DIR "${SOURCE_DIR}/maidsafe/vault/main.cc")
LIST(REMOVE_ITEM M_MSVAULT_DIR "${SOURCE_DIR}/maidsafe/vault/win_service.cc")
LIST(REMOVE_ITEM M_MSVAULT_DIR "${SOURCE_DIR}/maidsafe/vault/unix_deamon.cc")
LIST(APPEND STYLE_MSVAULT ${M_MSVAULT_C} ${M_MSVAULT_H})
FILE(GLOB T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/*.c*")
FILE(GLOB T_MAIDSAFE_H "${SOURCE_DIR}/tests/maidsafe/*.h*")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/testfuse.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/functionaltestclientcontroller.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/functionaltestauthentication.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/testclientcontroller.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/testpdvault.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/testbufferpackethandlerfunc.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/testimconnhandler.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/testimmessaging.cc")
LIST(APPEND T_MAIDSAFE_DIR ${T_MAIDSAFE_C} ${T_MAIDSAFE_H})
FILE(GLOB T_MAIN  "${SOURCE_DIR}/tests/main.cc")
QT4_ADD_RESOURCES(M_QT_C ${M_QT_QRC})
QT4_ADD_RESOURCES(M_QT_FB_C ${M_QT_QRC})
QT4_WRAP_UI(M_QT_UI ${M_QT_UI})
QT4_WRAP_CPP(M_QT_C ${M_QT_H})
QT4_WRAP_CPP(QT_FILE_BROWSER_CC ${SOURCE_DIR}/qt/widgets/file_browser.h)
SET(M_QT_FB_C ${M_QT_C} ${SOURCE_DIR}/qt/widgets/file_browser.cc ${QT_FILE_BROWSER_CC})
LIST(APPEND M_QT_C ${M_QT_H} ${M_QT_UI} ${M_QT_QRC})
LIST(APPEND M_QT_FB_C ${M_QT_FB_H} ${M_QT_UI} ${M_QT_QRC})
IF(APPLE)
  SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/l_fuse/fslinux.cc ${SOURCE_DIR}/fs/l_fuse/fusecpp.h)
ELSEIF(UNIX AND NOT APPLE)
  SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/l_fuse/fslinux.cc ${SOURCE_DIR}/fs/l_fuse/fusecpp.h)
ELSEIF(WIN32)
  SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/w_fuse/fswin.cc ${SOURCE_DIR}/fs/w_fuse/fswin.h)
ENDIF(APPLE)

###################################################################################################
# All Platforms:  Add exes and Create all PD libs                                                 #
###################################################################################################
LIST(REMOVE_DUPLICATES INCLUDE_DIRS)
INCLUDE_DIRECTORIES(${SOURCE_DIR} ${CMAKE_BINARY_DIR} ${INCLUDE_DIRS})
LINK_DIRECTORIES(${PD_BINARY_DIR})

IF(APPLE)
  ADD_EXECUTABLE(perpetualdata MACOSX_BUNDLE ${M_QT_C})
  ADD_EXECUTABLE(pdlocal MACOSX_BUNDLE  ${M_QT_C})
  ADD_EXECUTABLE(pdlightlocal MACOSX_BUNDLE  ${M_QT_FB_C} ${SOURCE_DIR}/fs/filesystem.cc)
ELSEIF((UNIX AND NOT APPLE) OR MSVC)
  ADD_EXECUTABLE(perpetualdata ${M_QT_C})
  ADD_EXECUTABLE(pdlocal ${M_QT_C})
  ADD_EXECUTABLE(pdlightlocal ${M_QT_FB_C} ${SOURCE_DIR}/fs/filesystem.cc)
ELSEIF(WIN32)
  ADD_EXECUTABLE(perpetualdata WIN32 ${M_QT_C})
  ADD_EXECUTABLE(pdlocal WIN32 ${M_QT_C})
  ADD_EXECUTABLE(pdlightlocal WIN32 ${M_QT_FB_C} ${SOURCE_DIR}/fs/filesystem.cc)
ENDIF()
IF(MSVC)
  SET_TARGET_PROPERTIES(perpetualdata pdlocal pdlightlocal PROPERTIES WIN32_EXECUTABLE TRUE)
ENDIF()
#ADD_EXECUTABLE(TESTfuse "${SOURCE_DIR}/tests/maidsafe/testfuse.cc")
ADD_EXECUTABLE(TESTnetworkclientcontroller "${SOURCE_DIR}/tests/maidsafe/functionaltestclientcontroller.cc")
ADD_EXECUTABLE(TESTfuncauth "${SOURCE_DIR}/tests/maidsafe/functionaltestauthentication.cc")
ADD_EXECUTABLE(TESTlocalclientcontroller "${SOURCE_DIR}/tests/maidsafe/testclientcontroller.cc")
ADD_EXECUTABLE(TESTpdvault "${SOURCE_DIR}/tests/maidsafe/testpdvault.cc")
ADD_EXECUTABLE(TESTbph "${SOURCE_DIR}/tests/maidsafe/testbufferpackethandlerfunc.cc")
ADD_EXECUTABLE(TESTmaidsafe ${T_MAIDSAFE_DIR})
ADD_EXECUTABLE(testvault "${SOURCE_DIR}/maidsafe/vault/main.cc")
ADD_EXECUTABLE(TESTimconnhndl ${T_MAIN} "${SOURCE_DIR}/tests/maidsafe/testimconnhandler.cc" "${SOURCE_DIR}/tests/maidsafe/testimmessaging.cc")
IF(WIN32)
  ADD_EXECUTABLE(vault "${SOURCE_DIR}/maidsafe/vault/win_service.cc")
ELSE()
  ADD_EXECUTABLE(vault "${SOURCE_DIR}/maidsafe/vault/unix_deamon.cc")
ENDIF()

SET(ALL_EXECUTABLES perpetualdata pdlocal pdlightlocal TESTnetworkclientcontroller TESTfuncauth TESTlocalclientcontroller
    TESTpdvault TESTbph TESTmaidsafe testvault TESTimconnhndl vault) # TESTfuse

ADD_LIBRARY(PDmaidsafelib STATIC ${M_MAIDSAFE_DIR})
ADD_LIBRARY(PDmsclientlib STATIC ${M_MSCLIENT_DIR})
ADD_LIBRARY(PDmsvaultlib STATIC ${M_MSVAULT_DIR})
ADD_LIBRARY(PDTESTmsclientlib STATIC ${M_MSCLIENT_DIR})
ADD_LIBRARY(PDfslib STATIC ${SOURCE_DIR}/fs/filesystem.cc ${FS_SOURCE_FILE})
ADD_LIBRARY(PDpbmsgslib STATIC ${M_PROTOBUF_DIR})

# Force renaming of exes to match standard CMake library renaming policy
IF((NOT MSVC) AND NOT (${CMAKE_BUILD_TYPE_DIR} MATCHES "kdev"))
  FOREACH(EXECUTABLE ${ALL_EXECUTABLES})
    SET_TARGET_PROPERTIES(${EXECUTABLE} PROPERTIES
                            DEBUG_OUTPUT_NAME ${EXECUTABLE}${CMAKE_DEBUG_POSTFIX}
                            RELWITHDEBINFO_OUTPUT_NAME ${EXECUTABLE}${CMAKE_RELWITHDEBINFO_POSTFIX}
                            MINSIZEREL_OUTPUT_NAME ${EXECUTABLE}${CMAKE_MINSIZEREL_POSTFIX})
  ENDFOREACH()
ENDIF()

###################################################################################################
# Builds                                                                                          #
###################################################################################################
SET(ALL_TARGET_LIBS PDmaidsafelib PDfslib PDpbmsgslib)

IF(NOT MSVC)
  SET(SYS_LIBS ${QT_LIBRARIES} ${Boost_LIBRARIES} ${Protobuf_LIBRARY} ${Glog_LIBRARY} ${maidsafe_dht_LIBRARY} ${Udt_LIBRARY} ${Cryptopp_LIBRARY} ${SYS_LIBS})
  TARGET_LINK_LIBRARIES(perpetualdata PDmsclientlib ${ALL_TARGET_LIBS} ${Dokan_LIBRARY} ${Breakpad_LIBRARY} ${SYS_LIBS})
  TARGET_LINK_LIBRARIES(pdlocal PDTESTmsclientlib ${ALL_TARGET_LIBS} ${Dokan_LIBRARY} ${Breakpad_LIBRARY} ${SYS_LIBS})
  TARGET_LINK_LIBRARIES(pdlightlocal PDTESTmsclientlib PDmaidsafelib PDpbmsgslib ${Breakpad_LIBRARY} ${SYS_LIBS})
  TARGET_LINK_LIBRARIES(vault PDmsvaultlib ${ALL_TARGET_LIBS} ${Breakpad_LIBRARY} ${SYS_LIBS})

  SET(TEST_LIBS PDmsclientlib PDmsvaultlib ${ALL_TARGET_LIBS} ${Gtest_LIBRARY} ${SYS_LIBS})
  TARGET_LINK_LIBRARIES(TESTmaidsafe ${TEST_LIBS} ${Gmock_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTpdvault ${TEST_LIBS})
  TARGET_LINK_LIBRARIES(TESTbph ${TEST_LIBS})
  TARGET_LINK_LIBRARIES(TESTimconnhndl ${TEST_LIBS})
  TARGET_LINK_LIBRARIES(TESTnetworkclientcontroller ${TEST_LIBS})
  TARGET_LINK_LIBRARIES(TESTfuncauth ${TEST_LIBS})
  #TARGET_LINK_LIBRARIES(TESTfuse ${TEST_LIBS})
  TARGET_LINK_LIBRARIES(TESTlocalclientcontroller PDTESTmsclientlib ${ALL_TARGET_LIBS} ${Gtest_LIBRARY} ${SYS_LIBS})
  TARGET_LINK_LIBRARIES(testvault PDmsclientlib PDmsvaultlib ${ALL_TARGET_LIBS} ${SYS_LIBS})
ELSE()
  SET(ALL_TARGET_LIBS ${ALL_TARGET_LIBS} ${QT_LIBRARIES})
  SET(DEBUG_LIBS ${Boost_DATE_TIME_LIBRARY_DEBUG} ${Boost_FILESYSTEM_LIBRARY_DEBUG} ${Boost_THREAD_LIBRARY_DEBUG}
      ${Boost_SYSTEM_LIBRARY_DEBUG} ${Boost_REGEX_LIBRARY_DEBUG} ${Protobuf_LIBRARY_DEBUG} ${Glog_LIBRARY_DEBUG}
      ${maidsafe_dht_LIBRARY_DEBUG} ${Udt_LIBRARY_DEBUG} ${Cryptopp_LIBRARY_DEBUG} ${SYS_LIBS})
  SET(RELEASE_LIBS ${Boost_DATE_TIME_LIBRARY_RELEASE} ${Boost_FILESYSTEM_LIBRARY_RELEASE} ${Boost_THREAD_LIBRARY_RELEASE}
      ${Boost_SYSTEM_LIBRARY_RELEASE} ${Boost_REGEX_LIBRARY_RELEASE} ${Protobuf_LIBRARY} ${Glog_LIBRARY}
      ${maidsafe_dht_LIBRARY} ${Udt_LIBRARY} ${Cryptopp_LIBRARY}  ${SYS_LIBS})

  TARGET_LINK_LIBRARIES(perpetualdata
                          PDmsclientlib
                          ${ALL_TARGET_LIBS}
                          ${Dokan_LIBRARY}
                          debug ${Breakpad_LIBRARY_DEBUG} optimized ${Breakpad_LIBRARY})
  TARGET_LINK_LIBRARIES(pdlocal
                          PDTESTmsclientlib
                          ${ALL_TARGET_LIBS}
                          ${Dokan_LIBRARY}
                          debug ${Breakpad_LIBRARY_DEBUG} optimized ${Breakpad_LIBRARY})
  TARGET_LINK_LIBRARIES(pdlightlocal
                          PDTESTmsclientlib
                          ${ALL_TARGET_LIBS}
                          debug ${Breakpad_LIBRARY_DEBUG} optimized ${Breakpad_LIBRARY})
  TARGET_LINK_LIBRARIES(vault
                          PDmsvaultlib
                          ${ALL_TARGET_LIBS}
                          debug ${Breakpad_LIBRARY_DEBUG} optimized ${Breakpad_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTlocalclientcontroller
                          PDTESTmsclientlib
                          ${ALL_TARGET_LIBS}
                          debug ${Gtest_LIBRARY_DEBUG} optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(testvault
                          PDmsclientlib
                          PDmsvaultlib
                          ${ALL_TARGET_LIBS})
  FOREACH (DLIB ${DEBUG_LIBS})
    TARGET_LINK_LIBRARIES(perpetualdata debug ${DLIB})
    TARGET_LINK_LIBRARIES(pdlocal debug ${DLIB})
    TARGET_LINK_LIBRARIES(pdlightlocal debug ${DLIB})
    TARGET_LINK_LIBRARIES(vault debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTlocalclientcontroller debug ${DLIB})
    TARGET_LINK_LIBRARIES(testvault debug ${DLIB})
  ENDFOREACH()
  FOREACH (RLIB ${RELEASE_LIBS})
    TARGET_LINK_LIBRARIES(perpetualdata optimized ${RLIB})
    TARGET_LINK_LIBRARIES(pdlocal optimized ${RLIB})
    TARGET_LINK_LIBRARIES(pdlightlocal optimized ${RLIB})
    TARGET_LINK_LIBRARIES(vault optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTlocalclientcontroller optimized ${RLIB})
    TARGET_LINK_LIBRARIES(testvault optimized ${RLIB})
  ENDFOREACH()

  SET(ALL_TARGET_LIBS PDmsclientlib PDmsvaultlib ${ALL_TARGET_LIBS})
  SET(DEBUG_TEST_LIBS ${Gtest_LIBRARY_DEBUG} ${DEBUG_LIBS})
  SET(RELEASE_TEST_LIBS ${Gtest_LIBRARY} ${RELEASE_LIBS})

  TARGET_LINK_LIBRARIES(TESTmaidsafe ${ALL_TARGET_LIBS})
  TARGET_LINK_LIBRARIES(TESTpdvault ${ALL_TARGET_LIBS})
  TARGET_LINK_LIBRARIES(TESTbph ${ALL_TARGET_LIBS})
  TARGET_LINK_LIBRARIES(TESTimconnhndl ${ALL_TARGET_LIBS})
  TARGET_LINK_LIBRARIES(TESTnetworkclientcontroller ${ALL_TARGET_LIBS})
  TARGET_LINK_LIBRARIES(TESTfuncauth ${ALL_TARGET_LIBS})
#  TARGET_LINK_LIBRARIES(TESTfuse ${ALL_TARGET_LIBS})

  TARGET_LINK_LIBRARIES(TESTmaidsafe debug ${Gmock_LIBRARY_DEBUG} optimized ${Gmock_LIBRARY})
  FOREACH (DLIB ${DEBUG_TEST_LIBS})
    TARGET_LINK_LIBRARIES(TESTmaidsafe debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTpdvault debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTbph debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTimconnhndl debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTnetworkclientcontroller debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTfuncauth debug ${DLIB})
#    TARGET_LINK_LIBRARIES(TESTfuse debug ${DLIB})
  ENDFOREACH()
  FOREACH (RLIB ${RELEASE_TEST_LIBS})
    TARGET_LINK_LIBRARIES(TESTmaidsafe optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTpdvault optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTbph optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTimconnhndl optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTnetworkclientcontroller optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTfuncauth optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(TESTfuse optimized ${RLIB})
  ENDFOREACH()
ENDIF()

###################################################################################################
# Compiler and linker flags - after all targets declared                                          #
###################################################################################################
IF(Glog_FOUND)
  ADD_DEFINITIONS(-DHAVE_GLOG)
ENDIF()
SET_TARGET_PROPERTIES(PDTESTmsclientlib PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)
SET_TARGET_PROPERTIES(TESTlocalclientcontroller PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)
SET_TARGET_PROPERTIES(pdlightlocal PROPERTIES COMPILE_FLAGS "-DPD_LIGHT -DLOCAL_PDVAULT")
SET(BUILD_SHARED_LIBS OFF)
IF(APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPD_APPLE -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
  SET_TARGET_PROPERTIES(pdlocal perpetualdata PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)
ELSEIF(UNIX AND NOT APPLE)
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra -Wall -DPD_LINUX -DPD_POSIX -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -Wredundant-decls -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -ansi -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  SET_TARGET_PROPERTIES(pdlocal perpetualdata PROPERTIES COMPILE_FLAGS "-w -DLOCAL_PDVAULT")
ELSEIF(WIN32)
  ADD_DEFINITIONS(-DPD_WIN32 -DWIN32 -D_WIN32 -D__WINDOWS__ -D__WIN32__ -DWIN32)
  ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x501)
  ADD_DEFINITIONS(-D_UNICODE -DUNICODE -D_BIND_TO_CURRENT_VCLIBS_VERSION=1)
  IF(MSVC)
    # flag to link to static version of Google Glog
    IF(Glog_FOUND)
      ADD_DEFINITIONS(-DGOOGLE_GLOG_DLL_DECL=)
    ENDIF()
    ADD_DEFINITIONS(-D__MSVC__ -DNOMINMAX -DBOOST_ALL_NO_LIB -DUDT_STATIC)
    SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Ot /Oy /GL /DNDEBUG /EHsc /MD /Gy /W3 /Zi /wd4503")
    SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D_DEBUG /DDEBUG /EHsc /MDd  /c /ZI /TP /wd4503")
    # CMake defaults to passing stack size in LINKER_FLAGS of 10MB.  Set this to windows default of 1MB
    STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
    # Given a link dir of "a/b/c", MSVC adds "a/b/c/" AND "a/b/c/CMAKE_BUILD_TYPE" as link dirs, so we
    # can't just use "LINK_DIRECTORIES" as some Google debug libs have the same name as the release version.
    LIST(REMOVE_DUPLICATES LIBS_DIRS)
    FOREACH(LIBS_DIR ${LIBS_DIRS})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
      SET(LINKER_LIBS_DIRS_RELEASE "${LINKER_LIBS_DIRS_RELEASE} /LIBPATH:\"${LIBS_DIR}\"")
    ENDFOREACH()
    LIST(REMOVE_DUPLICATES LIBS_DIRS_DEBUG)
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
    SET_TARGET_PROPERTIES(pdlocal perpetualdata PROPERTIES COMPILE_FLAGS "-DLOCAL_PDVAULT")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG") # -g -pg -fprofile-arcs -ftest-coverage")
    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I c:/usr/include -D_FORTIFY_SOURCE=2 -D__MINGW__ -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static -mthreads -D_GLIBCXX_USE_WCHAR_T")
    # SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--enable-auto-import")
    # SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET_TARGET_PROPERTIES(pdlocal perpetualdata PROPERTIES COMPILE_FLAGS "-w -DLOCAL_PDVAULT")
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

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(TEST_POSTFIX ${CMAKE_DEBUG_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
  SET(TEST_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
  SET(TEST_POSTFIX ${CMAKE_MINSIZEREL_POSTFIX})
ENDIF()

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

SET(BEHAVIOURAL_TEST_TIMEOUT 60)
SET(FUNCTIONAL_TEST_TIMEOUT 600)
SET(LOCAL_SYSTEM_TEST_TIMEOUT 1800)
SET(NETWORK_SYSTEM_TEST_TIMEOUT 3600)

FOREACH(GTEST_SOURCE_FILE ${T_MAIDSAFE_C})
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_NAMES REGEX ^TEST)
  FOREACH(GTEST_NAME ${GTEST_NAMES})
    STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_NAME ${GTEST_NAME})
    LIST(GET GTEST_NAME 1 GTEST_GROUP_NAME)
    LIST(GET GTEST_NAME 3 GTEST_NAME)
    LIST(FIND EXCLUDED_TESTS ${GTEST_NAME} THIS_GTEST_EXCLUDED)
    IF(THIS_GTEST_EXCLUDED EQUAL -1)
      IF("${GTEST_NAME}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
        ADD_TEST(${GTEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTmaidsafe${TEST_POSTFIX} --gtest_filter=*${GTEST_NAME}*)
        IF("${GTEST_NAME}" MATCHES "^FUNC_" OR "${GTEST_NAME}" MATCHES "^DISABLED_FUNC_")
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY LABELS Functional ${GTEST_GROUP_NAME})
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY TIMEOUT ${FUNCTIONAL_TEST_TIMEOUT})
        ELSEIF("${GTEST_NAME}" MATCHES "^BEH_" OR "${GTEST_NAME}" MATCHES "^DISABLED_BEH_")
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY LABELS Behavioural ${GTEST_GROUP_NAME})
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY TIMEOUT ${BEHAVIOURAL_TEST_TIMEOUT})
        ELSE()
          MESSAGE("")
          MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
          MESSAGE("")
          MESSAGE(AUTHOR_WARNING "${GTEST_NAME} should be named \"BEH_...\" or \"FUNC_...\" (with an optional \"DISABLED_\" prepended).")
          MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        ENDIF()
      ENDIF()
      SET(GTESTS ${GTESTS} ${GTEST_NAME})
    ENDIF()
  ENDFOREACH()
ENDFOREACH()

# Check for repeated test names
IF(NOT CMAKE_SUPPRESS_DEVELOPER_WARNINGS)
  STRING(REGEX REPLACE ";" "" CHECK_CACHED_COPY_OF_TESTS ${GTESTS})
  IF(NOT CHECK_CACHED_COPY_OF_TESTS STREQUAL CACHED_TESTS)
    SET(GTEST_NAMES ${GTESTS})
    LIST(LENGTH GTEST_NAMES GTESTS_COUNT)
    WHILE(GTESTS_COUNT GREATER 1)
      LIST(GET GTEST_NAMES 0 GTEST_NAME)
      LIST(REMOVE_AT GTEST_NAMES 0)
      STRING(REGEX MATCH ${GTEST_NAME} REPEATED_NAME ${GTEST_NAMES})
      IF(REPEATED_NAME)
        IF(NOT WARNING_MESSAGE)
          MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        ENDIF()
        SET(REPEATED_IN)
        FOREACH(GTEST_TEST_NAME ${GTEST_NAMES})
          STRING(REGEX MATCH ${GTEST_NAME} OTHER_REPEATED_NAME ${GTEST_TEST_NAME})
          IF(OTHER_REPEATED_NAME)
            SET(REPEATED_IN "${REPEATED_IN};${GTEST_TEST_NAME}")
          ENDIF()
        ENDFOREACH()
        SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n\"${REPEATED_NAME}\" repeated in tests\n")
        SET(WARNING_MESSAGE "${WARNING_MESSAGE}  -- ${REPEATED_NAME}\n")
        FOREACH(REPEATED_IN_TEST ${REPEATED_IN})
          SET(WARNING_MESSAGE "${WARNING_MESSAGE}  -- ${REPEATED_IN_TEST}\n")
        ENDFOREACH()
      ENDIF()
      LIST(LENGTH GTEST_NAMES GTESTS_COUNT)
    ENDWHILE()
    IF(WARNING_MESSAGE)
      MESSAGE(AUTHOR_WARNING ${WARNING_MESSAGE})
      MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
      MESSAGE("================================================================================")
    ENDIF()
    SET(CACHED_TESTS ${CHECK_CACHED_COPY_OF_TESTS} CACHE INTERNAL "List of Google Tests in TESTmaidsafe.")
  ENDIF()
ENDIF()

IF(NOT ${MAIDSAFE_TEST_TYPE} MATCHES "BEH")
  LIST(FIND EXCLUDED_TESTS Testnetworkclientcontroller TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Testnetworkclientcontroller ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTnetworkclientcontroller${TEST_POSTFIX})
    SET_PROPERTY(TEST Testnetworkclientcontroller PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Testnetworkclientcontroller PROPERTY LABELS Functional ClientController NetworkCC)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Testlocalclientcontroller TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Testlocalclientcontroller ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTlocalclientcontroller${TEST_POSTFIX})
    SET_PROPERTY(TEST Testlocalclientcontroller PROPERTY TIMEOUT ${LOCAL_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Testlocalclientcontroller PROPERTY LABELS Functional ClientController LocalCC)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Testpdvault TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Testpdvault ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTpdvault${TEST_POSTFIX})
    SET_PROPERTY(TEST Testpdvault PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Testpdvault PROPERTY LABELS Functional PdVault)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Testbph TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Testbph ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTbph${TEST_POSTFIX})
    SET_PROPERTY(TEST Testbph PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Testbph PROPERTY LABELS Functional BufferPacketHandler)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Testnetworkauthentication TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Testnetworkauthentication ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTfuncauth${TEST_POSTFIX})
    SET_PROPERTY(TEST Testnetworkauthentication PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Testnetworkauthentication PROPERTY LABELS Functional Authentication)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS Testimconnhndl TEST_EXCLUDED)
  IF(TEST_EXCLUDED EQUAL -1)
    ADD_TEST(Testimconnhndl ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTimconnhndl${TEST_POSTFIX})
    SET_PROPERTY(TEST Testimconnhndl PROPERTY TIMEOUT ${NETWORK_SYSTEM_TEST_TIMEOUT})
    SET_PROPERTY(TEST Testimconnhndl PROPERTY LABELS Functional InstantMessaging)
  ENDIF()

  LIST(FIND EXCLUDED_TESTS STYLE_CHECK TEST_EXCLUDED)
  IF((TEST_EXCLUDED EQUAL -1) AND PYTHONINTERP_FOUND)
    IF(UNIX)
      ADD_TEST(STYLE_CHECK ${SOURCE_DIR}/cpplint.py ${STYLE_MAIDSAFE})
      SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
    ELSE()
      ADD_TEST(STYLE_CHECK finderrorsall.bat)
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
MESSAGE("Package version is set to \"${pddate}\"")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Tests included: \"${MAIDSAFE_TEST_TYPE}\"")
MESSAGE("")
MESSAGE("    To include all tests,                     cmake ../.. -DMAIDSAFE_TEST_TYPE=_")
MESSAGE("    To include behavioural tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE("    To include functional tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=FUNC")
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
MESSAGE("    To exclude a test,                    cmake ../.. -DEXCLUDE_TEST=<Test Name>")
MESSAGE("    To re-include a test,                 cmake ../.. -DINCLUDE_TEST=<Test Name>")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Build type is set to \"${CMAKE_BUILD_TYPE}\"")
IF(NOT MSVC)
  IF((NOT MAIDSAFE_DHT_BUILD_TYPE MATCHES "Debug") OR
     (NOT MAIDSAFE_DHT_BUILD_TYPE MATCHES "RelWithDebInfo") OR
     (NOT MAIDSAFE_DHT_BUILD_TYPE MATCHES "MinSizeRel"))
    SET(MAIDSAFE_DHT_BUILD_TYPE Release)
  ENDIF()
  MESSAGE("Linking to \"${MAIDSAFE_DHT_BUILD_TYPE}\" build of maidsafe-dht, cryptopp & udt")
ENDIF()
MESSAGE("")
MESSAGE("    To alter build type (e.g. to Debug),    cmake ../.. -DCMAKE_BUILD_TYPE=Debug")
IF(NOT MSVC)
  MESSAGE("")
  MESSAGE("    To link to (e.g. Debug) build of maidsafe-dht, cryptopp & udt,")
  MESSAGE("                                     cmake ../.. -DMAIDSAFE_DHT_BUILD_TYPE=Debug")
  MESSAGE("")
ENDIF()
MESSAGE("    Options are Release, Debug, RelWithDebInfo, MinSizeRel")
MESSAGE("================================================================================")
MESSAGE("")


# BitRock InstallBuilder
IF(CMAKE_BUILD_TYPE MATCHES Release)
  INCLUDE(${PD_SOURCE_DIR}/build/maidsafe_FindInstallBuilder.cmake)
  IF(InstallBuilder_BUILDER_EXE AND InstallBuilder_CUSTOMISE_EXE)
    ADD_CUSTOM_TARGET(perpetualdataInstaller ALL ${InstallBuilder_CUSTOMISE_EXE} build ${PD_SOURCE_DIR}/installer/bitrock/autoup_pd.xml
                      COMMAND ${InstallBuilder_BUILDER_EXE} build ${PD_SOURCE_DIR}/installer/bitrock/pd.xml DEPENDS perpetualdata vault)
    ADD_CUSTOM_TARGET(pdlightlocalInstaller ALL ${InstallBuilder_CUSTOMISE_EXE} build ${PD_SOURCE_DIR}/installer/bitrock/autoup_pdlightlocal.xml
                      COMMAND ${InstallBuilder_BUILDER_EXE} build ${PD_SOURCE_DIR}/installer/bitrock/pdlightlocal.xml DEPENDS pdlightlocal)
  ENDIF()
ENDIF()
