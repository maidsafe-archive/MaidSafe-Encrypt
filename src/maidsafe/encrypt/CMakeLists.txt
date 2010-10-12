# ============================================================================ #
#                                                                              #
# Copyright [2010] maidsafe.net limited                                        #
#                                                                              #
# Description:  CMakeList for Encrypt project.                                 #
# Version:      1.0                                                            #
# Created:      2010-10-12-01.53.23                                            #
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


SET_DIRECTORY_PROPERTIES(PROPERTIES INCLUDE_DIRECTORIES "")

FILE(GLOB SOURCE_FILES_ENCRYPT_DIR "${SRC_MAIDSAFE}/encrypt/*.cc")
FILE(GLOB HEADER_FILES_ENCRYPT_DIR "${SRC_MAIDSAFE}/encrypt/*.h")
SET(ALL_FILES_ENCRYPT_DIR ${SOURCE_FILES_ENCRYPT_DIR} ${HEADER_FILES_ENCRYPT_DIR})
SOURCE_GROUP("encrpyt Source Files" FILES ${SOURCE_FILES_ENCRYPT_DIR})
SOURCE_GROUP("encrypt Header Files" FILES ${HEADER_FILES_ENCRYPT_DIR})

FILE(GLOB ALL_FILES_ENCRYPT_TESTS_DIR "${SRC_MAIDSAFE}/encrypt/tests/*.cc" "${SRC_MAIDSAFE}/encrypt/tests/*.h")

ADD_EXECUTABLE(TESTencrypt ${ALL_FILES_ENCRYPT_TESTS_DIR} ${TESTS_MAIN})
ADD_LIBRARY(Encrypt STATIC ${ALL_FILES_ENCRYPT_DIR})

IF(MSVC)
  INSTALL(TARGETS Encrypt
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib)
ELSE()
  SET_TARGET_PROPERTIES(TESTencrypt PROPERTIES
                          DEBUG_OUTPUT_NAME TESTencrypt${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTencrypt${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTencrypt${CMAKE_MINSIZEREL_POSTFIX})
  INSTALL(TARGETS Encrypt
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib)
ENDIF()

IF(APPLE)
  SET_TARGET_PROPERTIES(Encrypt PROPERTIES COMPILE_FLAGS "-O2 -fPIC -w -finline-functions")
  TARGET_LINK_LIBRARIES(TESTencrypt Encrypt)
ELSEIF(UNIX AND NOT APPLE)
  SET_TARGET_PROPERTIES(Encrypt PROPERTIES COMPILE_FLAGS "-O2 -fPIC -w -pipe -finline-functions")
  TARGET_LINK_LIBRARIES(TESTencrypt Encrypt)
ELSEIF(WIN32 AND NOT MSVC)
  SET_TARGET_PROPERTIES(Encrypt PROPERTIES COMPILE_FLAGS "-O2 -mthreads -w -finline-functions -D_WIN32_WINNT=0x0501")
  TARGET_LINK_LIBRARIES(TESTencrypt Encrypt odbc32 odbccp32 Ws2_32)
ELSEIF(WIN32 AND MSVC)
  CMAKE_POLICY(SET CMP0008 NEW)
  SET_TARGET_PROPERTIES(Encrypt PROPERTIES COMPILE_FLAGS "/D_WINDOWS /DUSE_PRECOMPILED_HEADERS /DWIN32 /D_VC80_UPGRADE=0x0710 /EHsc /W3")
  SET_TARGET_PROPERTIES(TESTencrypt PROPERTIES COMPILE_FLAGS "/D_CONSOLE /DWIN32 /D_VC80_UPGRADE=0x0710 /D_MBCS /EHsc /W3 /Zm400"
                                               LINK_FLAGS "/STACK:1048576"
                                               LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG"
                                               LINK_FLAGS_RELWITHDEBINFO "/LTCG"
                                               LINK_FLAGS_MINSIZEREL "/LTCG")
  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Oy /GL /DNDEBUG /GF /MD /Gy /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Oi /D_DEBUG /MDd /arch:SSE /ZI")
  TARGET_LINK_LIBRARIES(TESTencrypt Encrypt)
ENDIF()
