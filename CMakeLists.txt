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
FILE(WRITE ${${PROJECT_NAME}_BINARY_DIR}/CTestCustom.cmake "SET(CTEST_CUSTOM_COVERAGE_EXCLUDE \${CTEST_CUSTOM_COVERAGE_EXCLUDE} \"*.pb.*\" \"tests/\" \"tools/\")\n\n")

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
FILE(GLOB_RECURSE PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-encrypt/*.proto")
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindProtobuf.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Protobuf_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Protobuf_LIBRARY_DIR_DEBUG})

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
SET(SRC_MAIDSAFE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-encrypt")

####    CODE    ####
FILE(GLOB SOURCE_FILES "${SRC_MAIDSAFE}/*.cc")
FILE(GLOB HEADER_FILES "${SRC_MAIDSAFE}/*.h")
SET(ALL_FILES ${SOURCE_FILES} ${HEADER_FILES})

####    TESTS    ####
FILE(GLOB ALL_FILES_TESTS_DIR "${SRC_MAIDSAFE}/tests/*.cc" "${SRC_MAIDSAFE}/tests/*.h")

###################################################################################################
# All Platforms:  Create libs and executables                                                     #
###################################################################################################
SET(BEHAVIOURAL_TEST_TIMEOUT 60)
SET(FUNCTIONAL_TEST_TIMEOUT 600)

ADD_LIBRARY(encrypt STATIC ${ALL_FILES})
ADD_EXECUTABLE(TESTencrypt ${ALL_FILES_TESTS_DIR})

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
  # When this target is built, it removes all .gcda files from the build directory and its subdirectories
  ADD_CUSTOM_TARGET(CleanCoverage COMMAND ${CMAKE_COMMAND} -DSEARCH_DIR=${CMAKE_BINARY_DIR} -P ${${PROJECT_NAME}_ROOT}/build/clean_coverage.cmake)
  # This target builds the reference manual using Doxygen
  ADD_CUSTOM_TARGET(Reference COMMAND doxygen WORKING_DIRECTORY ${${PROJECT_NAME}_ROOT})
ENDIF()

###################################################################################################
# Compiler and linker flags - after all targets declared                                          #
###################################################################################################
IF(Glog_FOUND)
  ADD_DEFINITIONS(-DHAVE_GLOG)
ENDIF()
ADD_DEFINITIONS(-DBOOST_FILESYSTEM_NO_DEPRECATED -DBOOST_FILESYSTEM_VERSION=3)
TARGET_LINK_LIBRARIES(encrypt maidsafe_dht_LIBRARY ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Protobuf_LIBRARY})
TARGET_LINK_LIBRARIES(TESTencrypt encrypt ${Gtest_LIBRARY})
IF(UNIX)
  IF(APPLE)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOSX -DPD_APPLE -DBSD -D__FreeBSD__=10 -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINUX -DPD_LINUX -DPD_POSIX -Wextra -Wall -Wfloat-equal -Wlong-long -Wstrict-overflow=5 -Wredundant-decls -Wuninitialized -Wunused-function")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -std=c++0x -Weffc++ -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64")
  ENDIF()
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -DDEBUG -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wuninitialized")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
  SET_TARGET_PROPERTIES(encrypt PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions")
ELSEIF(WIN32)
  IF(MSVC)
    CMAKE_POLICY(SET CMP0008 NEW)
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

SET(TEST_EXECUTABLES TESTencrypt)
FOREACH(TEST_EXECUTABLE ${TEST_EXECUTABLES})
  IF(TEST_EXECUTABLE STREQUAL "TESTencrypt")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TESTS_DIR})
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
  LIST(FIND EXCLUDED_TESTS STYLE_CHECK TEST_EXCLUDED)
  IF((TEST_EXCLUDED EQUAL -1) AND PYTHONINTERP_FOUND)
    IF(UNIX)
      SET(STYLE_ALL ${STYLE})
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
