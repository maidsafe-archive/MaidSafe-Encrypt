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


SET(LIBS_DIRS ${Boost_LIBRARY_DIRS} ${maidsafe_dht_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${Boost_LIBRARY_DIRS} ${maidsafe_dht_LIBRARY_DIR_DEBUG})
SET(TEST_LIBS_DIRS ${LIBS_DIRS} ${Gtest_LIBRARY_DIR})
SET(TEST_LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Gtest_LIBRARY_DIR_DEBUG})

SET_PROPERTY(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES
               ${${PROJECT_NAME}_SOURCE_DIR} ${Boost_INCLUDE_DIR} ${maidsafe_dht_INCLUDE_DIR} ${Protobuf_INCLUDE_DIR} ${Gtest_INCLUDE_DIR})

FILE(GLOB SOURCE_FILES_ENCRYPT_DIR "${SRC_MAIDSAFE}/encrypt/*.cc")
FILE(GLOB HEADER_FILES_ENCRYPT_DIR "${SRC_MAIDSAFE}/encrypt/*.h")
SET(ALL_FILES_ENCRYPT_DIR ${SOURCE_FILES_ENCRYPT_DIR} ${HEADER_FILES_ENCRYPT_DIR})
SOURCE_GROUP("encrypt Source Files" FILES ${SOURCE_FILES_ENCRYPT_DIR})
SOURCE_GROUP("encrypt Header Files" FILES ${HEADER_FILES_ENCRYPT_DIR})

FILE(GLOB ALL_FILES_ENCRYPT_TESTS_DIR "${SRC_MAIDSAFE}/encrypt/tests/*.cc" "${SRC_MAIDSAFE}/encrypt/tests/*.h")

ADD_LIBRARY(encrypt STATIC ${ALL_FILES_ENCRYPT_DIR})
ADD_EXECUTABLE(TESTencrypt ${ALL_FILES_ENCRYPT_TESTS_DIR})

IF(MSVC)
  INSTALL(TARGETS encrypt
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib)
ELSE()
  SET_TARGET_PROPERTIES(TESTencrypt PROPERTIES
                          DEBUG_OUTPUT_NAME TESTencrypt${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTencrypt${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTencrypt${CMAKE_MINSIZEREL_POSTFIX})
  INSTALL(TARGETS encrypt
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib)
ENDIF()


IF(UNIX)
  TARGET_LINK_LIBRARIES(encrypt ${Boost_FILESYSTEM_LIBRARY_RELEASE} ${Boost_SYSTEM_LIBRARY_RELEASE} ${maidsafe_dht_LIBRARY} ${Cryptopp_LIBRARY} pthread)
  TARGET_LINK_LIBRARIES(TESTencrypt encrypt ${Gtest_LIBRARY})
  IF(APPLE)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOSX -DPD_APPLE -DBSD -D__FreeBSD__=10 -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINUX -DPD_LINUX -DPD_POSIX -Wextra -Wall -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -Wredundant-decls -Wuninitialized -Wunused-function")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -ansi -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
  ENDIF()
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -DDEBUG -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wuninitialized")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
  SET_TARGET_PROPERTIES(encrypt PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions")
ELSEIF(WIN32)
  IF(MSVC)
    CMAKE_POLICY(SET CMP0008 NEW)
    TARGET_LINK_LIBRARIES(encrypt
                            debug ${Boost_FILESYSTEM_LIBRARY_DEBUG} optimized ${Boost_FILESYSTEM_LIBRARY_RELEASE}
                            debug ${Boost_SYSTEM_LIBRARY_DEBUG} optimized ${Boost_SYSTEM_LIBRARY_RELEASE}
                            debug ${maidsafe_dht_LIBRARY_DEBUG} optimized ${maidsafe_dht_LIBRARY}
                            debug ${Cryptopp_LIBRARY_DEBUG} optimized ${Cryptopp_LIBRARY})
    TARGET_LINK_LIBRARIES(TESTencrypt encrypt debug ${Gtest_LIBRARY_DEBUG} optimized ${Gtest_LIBRARY})
    # flag to link to static version of Google Glog
    IF(Glog_FOUND)
      ADD_DEFINITIONS(-DGOOGLE_GLOG_DLL_DECL=)
    ENDIF()
    ADD_DEFINITIONS(-DPD_WIN32 -DWIN32 -D_WIN32 -D__WIN32__ -D__WINDOWS__ -D_WINDOWS)
    ADD_DEFINITIONS(-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x501)
    ADD_DEFINITIONS(-D_UNICODE -DUNICODE -D_BIND_TO_CURRENT_VCLIBS_VERSION=1)
    ADD_DEFINITIONS(-D__MSVC__ -DNOMINMAX -DBOOST_ALL_NO_LIB)
    SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Ot /Oy /GL /D \"NDEBUG\" /EHsc /GF /MD /Gy /W3 /Zi") #  /wd4503
    SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Oi /Ot /Oy /D \"_DEBUG\" /D \"DEBUG\" /EHsc /MDd /W3 /c /arch:SSE /ZI /TP") #  /wd4503
    # CMake defaults to passing stack size in LINKER_FLAGS of 10MB.  Set this to windows default of 1MB
    STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
    # Given a link dir of "a/b/c", MSVC adds "a/b/c/" AND "a/b/c/CMAKE_BUILD_TYPE" as link dirs, so we
    # can't just use "LINK_DIRECTORIES" as some Google debug libs have the same name as the release version.
    FOREACH(LIBS_DIR ${LIBS_DIRS})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
      SET(LINKER_LIBS_DIRS_RELEASE "${LINKER_LIBS_DIRS_RELEASE} /LIBPATH:\"${LIBS_DIR}\"")
    ENDFOREACH()
    FOREACH(LIBS_DIR ${LIBS_DIRS_DEBUG})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
      SET(LINKER_LIBS_DIRS_DEBUG "${LINKER_LIBS_DIRS_DEBUG} /LIBPATH:\"${LIBS_DIR}\"")
    ENDFOREACH()
    FOREACH(LIBS_DIR ${TEST_LIBS_DIRS})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
      SET(TEST_LINKER_LIBS_DIRS_RELEASE "${TEST_LINKER_LIBS_DIRS_RELEASE} /LIBPATH:\"${LIBS_DIR}\"")
    ENDFOREACH()
    FOREACH(LIBS_DIR ${TEST_LIBS_DIRS_DEBUG})
      STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
      SET(TEST_LINKER_LIBS_DIRS_DEBUG "${TEST_LINKER_LIBS_DIRS_DEBUG} /LIBPATH:\"${LIBS_DIR}\"")
    ENDFOREACH()
    SET_TARGET_PROPERTIES(encrypt PROPERTIES
                              COMPILE_FLAGS "/D_VC80_UPGRADE=0x0710"
                              LINK_FLAGS "/STACK:1048576"
                              LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                              LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                              LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                              LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
    SET_TARGET_PROPERTIES(TESTencrypt PROPERTIES
                              COMPILE_FLAGS "/D_CONSOLE /D_VC80_UPGRADE=0x0710 /D_MBCS"
                              LINK_FLAGS "/STACK:1048576"
                              LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${TEST_LINKER_LIBS_DIRS_RELEASE}"
                              LINK_FLAGS_DEBUG "${TEST_LINKER_LIBS_DIRS_DEBUG}"
                              LINK_FLAGS_RELWITHDEBINFO "/LTCG ${TEST_LINKER_LIBS_DIRS_DEBUG}"
                              LINK_FLAGS_MINSIZEREL "/LTCG ${TEST_LINKER_LIBS_DIRS_DEBUG}")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG") # -g -pg -fprofile-arcs -ftest-coverage")
    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2 -D__MINGW__ -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static -mthreads -D_GLIBCXX_USE_WCHAR_T")
    # SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--enable-auto-import")
    # SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
    SET_TARGET_PROPERTIES(encrypt PROPERTIES COMPILE_FLAGS "-O2 -mthreads -w -finline-functions -D_WIN32_WINNT=0x0501")
    TARGET_LINK_LIBRARIES(TESTencrypt encrypt odbc32 odbccp32 Ws2_32)
  ENDIF()
ENDIF()

