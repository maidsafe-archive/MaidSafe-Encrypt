# ============================================================================ #
#                                                                              #
# Copyright [2010] maidsafe.net limited                                        #
#                                                                              #
# Description:  See below.                                                     #
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
#                                                                              #
#  Module used to locate maidsafe_dht, cryptopp and udt libs and headers.  It  #
#  is assumed that the libs for the three targets are all in the same location #
#  and likewise for their API header files.                                    #
#                                                                              #
#  If using MSVC, locates Debug and Release libs.  Otherwise, it locates the   #
#  type indicated by variable MAIDSAFE_DHT_BUILD_TYPE.  This can be Release,   #
#  Debug, RelWithDebInfo, or MinSizeRel.  If not set, Release libs are         #
#  searched for.                                                               #
#                                                                              #
#  Settable variables to aid with finding maidsafe_dht are:                    #
#    MAIDSAFE_DHT_LIB_DIR, MAIDSAFE_DHT_INC_DIR and MAIDSAFE_DHT_ROOT_DIR      #
#                                                                              #
#  If all libs are found, a target named maidsafe_dht_LIBRARY is added with    #
#  appropriate dependencies set.                                               #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    maidsafe_dht_INCLUDE_DIR and maidsafe_dht_LIBRARY_DIR.                    #
#                                                                              #
#  For MSVC, maidsafe_dht_LIBRARY_DIR_DEBUG, is also set and cached.           #
#                                                                              #
#==============================================================================#


UNSET(maidsafe_dht_INCLUDE_DIR CACHE)
UNSET(maidsafe_dht_LIBRARY_DIR CACHE)
UNSET(maidsafe_dht_LIBRARY_DIR_DEBUG CACHE)
UNSET(MAIDSAFE_DHT_LIBRARY CACHE)
UNSET(MAIDSAFE_DHT_LIBRARY_DEBUG CACHE)
UNSET(CRYPTOPP_LIBRARY CACHE)
UNSET(CRYPTOPP_LIBRARY_DEBUG CACHE)
UNSET(UDT_LIBRARY CACHE)
UNSET(UDT_LIBRARY_DEBUG CACHE)

IF(MAIDSAFE_DHT_LIB_DIR)
  SET(MAIDSAFE_DHT_LIB_DIR ${MAIDSAFE_DHT_LIB_DIR} CACHE PATH "Path to maidsafe_dht libraries directory" FORCE)
ENDIF()
IF(MAIDSAFE_DHT_ROOT_DIR)
  SET(MAIDSAFE_DHT_ROOT_DIR ${MAIDSAFE_DHT_ROOT_DIR} CACHE PATH "Path to maidsafe_dht root directory" FORCE)
ELSEIF(DEFAULT_THIRD_PARTY_ROOT)
  FIND_THIRD_PARTY_PROJECT(MAIDSAFE_DHT_ROOT_DIR maidsafe-dht ${DEFAULT_THIRD_PARTY_ROOT})
  IF(MAIDSAFE_DHT_ROOT_DIR_CACHED)
    SET(MAIDSAFE_DHT_ROOT_DIR ${MAIDSAFE_DHT_ROOT_DIR_CACHED})
  ENDIF()
ENDIF()

IF(MSVC)
  IF(CMAKE_CL_64)
    SET(DHT_LIBPATH_SUFFIX build/Win_MSVC/bin/x64/Release build/Win_MSVC/bin/x64/Debug build/Win_MSVC/bin/x64/RelWithDebInfo build/Win_MSVC/bin/x64/MinSizeRel lib)
  ELSE()
    SET(DHT_LIBPATH_SUFFIX build/Win_MSVC/bin/win32/Release build/Win_MSVC/bin/win32/Debug build/Win_MSVC/bin/win32/RelWithDebInfo build/Win_MSVC/bin/win32/MinSizeRel lib)
  ENDIF()
  FIND_LIBRARY(MAIDSAFE_DHT_LIBRARY NAMES maidsafe_dht PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  FIND_LIBRARY(MAIDSAFE_DHT_LIBRARY_DEBUG NAMES maidsafe_dht${CMAKE_DEBUG_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  FIND_LIBRARY(CRYPTOPP_LIBRARY NAMES cryptopp PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  FIND_LIBRARY(CRYPTOPP_LIBRARY_DEBUG NAMES cryptopp${CMAKE_DEBUG_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  FIND_LIBRARY(UDT_LIBRARY NAMES udt PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  FIND_LIBRARY(UDT_LIBRARY_DEBUG NAMES udt${CMAKE_DEBUG_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
ELSE()
  IF(WIN32)
    SET(DHT_LIBPATH_SUFFIX build/Win_MinGW/bin)
  ELSEIF(APPLE)
    SET(DHT_LIBPATH_SUFFIX build/OSX/bin)
  ELSEIF(UNIX)
    SET(DHT_LIBPATH_SUFFIX build/Linux/bin)
  ENDIF()
  IF(MAIDSAFE_DHT_BUILD_TYPE MATCHES "Debug")
    FIND_LIBRARY(MAIDSAFE_DHT_LIBRARY NAMES maidsafe_dht${CMAKE_DEBUG_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(CRYPTOPP_LIBRARY NAMES cryptopp${CMAKE_DEBUG_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(UDT_LIBRARY NAMES udt${CMAKE_DEBUG_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  ELSEIF(MAIDSAFE_DHT_BUILD_TYPE MATCHES "RelWithDebInfo")
    FIND_LIBRARY(MAIDSAFE_DHT_LIBRARY NAMES maidsafe_dht${CMAKE_RELWITHDEBINFO_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(CRYPTOPP_LIBRARY NAMES cryptopp${CMAKE_RELWITHDEBINFO_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(UDT_LIBRARY NAMES udt${CMAKE_RELWITHDEBINFO_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  ELSEIF(MAIDSAFE_DHT_BUILD_TYPE MATCHES "MinSizeRel")
    FIND_LIBRARY(MAIDSAFE_DHT_LIBRARY NAMES maidsafe_dht${CMAKE_MINSIZEREL_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(CRYPTOPP_LIBRARY NAMES cryptopp${CMAKE_MINSIZEREL_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(UDT_LIBRARY NAMES udt${CMAKE_MINSIZEREL_POSTFIX} PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  ELSE()
    FIND_LIBRARY(MAIDSAFE_DHT_LIBRARY NAMES maidsafe_dht PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(CRYPTOPP_LIBRARY NAMES cryptopp PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
    FIND_LIBRARY(UDT_LIBRARY NAMES udt PATHS ${MAIDSAFE_DHT_LIB_DIR} ${MAIDSAFE_DHT_ROOT_DIR} PATH_SUFFIXES ${DHT_LIBPATH_SUFFIX})
  ENDIF()
ENDIF()

IF(MAIDSAFE_DHT_INC_DIR)
  SET(MAIDSAFE_DHT_INC_DIR ${MAIDSAFE_DHT_INC_DIR} CACHE PATH "Path to maidsafe_dht include directory" FORCE)
ENDIF()
FIND_PATH(maidsafe_dht_INCLUDE_DIR maidsafe/maidsafe-dht_config.h PATHS ${MAIDSAFE_DHT_INC_DIR} ${MAIDSAFE_DHT_ROOT_DIR}/build/Win_MSVC/include ${MAIDSAFE_DHT_ROOT_DIR}/include)
IF(NOT maidsafe_dht_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find maidsafe-dht_config.h\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download maidsafe-dht at http://code.google.com/p/maidsafe-dht\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If maidsafe-dht is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_INC_DIR=<Path to maidsafe-dht include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_ROOT_DIR=<Path to maidsafe-dht root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

# Check version maidsafe-dht version is OK
FILE(STRINGS ${maidsafe_dht_INCLUDE_DIR}/maidsafe/maidsafe-dht_config.h VERSION_LINE REGEX "MAIDSAFE_DHT_VERSION")
STRING(REPLACE "#define MAIDSAFE_DHT_VERSION " "" INSTALLED_DHT_VERSION ${VERSION_LINE})
FIND_FILE(MAIDSAFE_DOT_H maidsafe.h ${${PROJECT_NAME}_ROOT}/src/maidsafe/common)
FILE(STRINGS ${MAIDSAFE_DOT_H} VERSION_LINE REGEX "#define THIS_MAIDSAFE_DHT_VERSION")
STRING(REPLACE "#define THIS_MAIDSAFE_DHT_VERSION " "" THIS_DHT_VERSION ${VERSION_LINE})
IF(NOT ${THIS_DHT_VERSION} MATCHES ${INSTALLED_DHT_VERSION})
  SET(ERROR_MESSAGE "\nInstalled version of maidsafe-dht has MAIDSAFE_DHT_VERSION == ${INSTALLED_DHT_VERSION}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}This project has MAIDSAFE_DHT_VERSION == ${THIS_DHT_VERSION}\n")
  IF(${THIS_DHT_VERSION} LESS ${INSTALLED_DHT_VERSION})
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Please update ${MAIDSAFE_DOT_H}\n")
  ELSE()
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Please update maidsafe-dht.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download maidsafe-dht at http://code.google.com/p/maidsafe-dht\n")
  ENDIF()
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

GET_FILENAME_COMPONENT(DHT_LIBRARY_DIR ${MAIDSAFE_DHT_LIBRARY} PATH)
GET_FILENAME_COMPONENT(CRYPTO_LIBRARY_DIR ${CRYPTOPP_LIBRARY} PATH)
GET_FILENAME_COMPONENT(UDT_LIBRARY_DIR ${UDT_LIBRARY} PATH)
SET(CHECK_LIB_DIR_UNIQUE ${DHT_LIBRARY_DIR} ${CRYPTO_LIBRARY_DIR} ${UDT_LIBRARY_DIR})
IF(CHECK_LIB_DIR_UNIQUE)
  LIST(REMOVE_DUPLICATES CHECK_LIB_DIR_UNIQUE)
  LIST(LENGTH CHECK_LIB_DIR_UNIQUE CHECK_LIB_DIR_UNIQUE_SIZE)
  IF(NOT CHECK_LIB_DIR_UNIQUE_SIZE EQUAL 1)
    SET(ERROR_MESSAGE "\nmaidsafe-dht, cryptopp and udt libraries must be in a single directory.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Found maidsafe-dht in ${DHT_LIBRARY_DIR}\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Found cryptopp in ${CRYPTO_LIBRARY_DIR}\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}Found udt in ${UDT_LIBRARY_DIR}\n")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ELSE()
  SET(ERROR_MESSAGE "\nCould not find maidsafe-dht library.\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/maidsafe-dht\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If maidsafe-dht is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_LIB_DIR=<Path to maidsafe-dht libraries directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_ROOT_DIR=<Path to maidsafe-dht root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()
SET(maidsafe_dht_LIBRARY_DIR ${CHECK_LIB_DIR_UNIQUE} CACHE PATH "Path to maidsafe_dht libraries directory" FORCE)

IF(MSVC)
  GET_FILENAME_COMPONENT(DHT_LIBRARY_DIR_DEBUG ${MAIDSAFE_DHT_LIBRARY_DEBUG} PATH)
  GET_FILENAME_COMPONENT(CRYPTO_LIBRARY_DIR_DEBUG ${CRYPTOPP_LIBRARY_DEBUG} PATH)
  GET_FILENAME_COMPONENT(UDT_LIBRARY_DIR_DEBUG ${UDT_LIBRARY_DEBUG} PATH)
  SET(CHECK_LIB_DIR_DEBUG_UNIQUE ${DHT_LIBRARY_DIR_DEBUG} ${CRYPTO_LIBRARY_DIR_DEBUG} ${UDT_LIBRARY_DIR_DEBUG})
  IF(CHECK_LIB_DIR_DEBUG_UNIQUE)
    LIST(REMOVE_DUPLICATES CHECK_LIB_DIR_DEBUG_UNIQUE)
    LIST(LENGTH CHECK_LIB_DIR_DEBUG_UNIQUE CHECK_LIB_DIR_DEBUG_UNIQUE_SIZE)
    IF(NOT CHECK_LIB_DIR_DEBUG_UNIQUE_SIZE EQUAL 1)
      SET(ERROR_MESSAGE "\nmaidsafe-dht, cryptopp and udt Debug libraries must be in a single directory.\n")
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}Found Debug maidsafe-dht in ${DHT_LIBRARY_DIR_DEBUG}\n")
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}Found Debug cryptopp in ${CRYPTO_LIBRARY_DIR_DEBUG}\n")
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}Found Debug udt in ${UDT_LIBRARY_DIR_DEBUG}\n")
      MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
    ENDIF()
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find maidsafe-dht_d Debug library.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/maidsafe-dht\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If maidsafe-dht is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_ROOT_DIR=<Path to maidsafe-dht root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  SET(maidsafe_dht_LIBRARY_DIR_DEBUG ${CHECK_LIB_DIR_DEBUG_UNIQUE} CACHE PATH "Path to maidsafe_dht libraries directory" FORCE)
ENDIF()

SET(LIBRARIES_LIST ${MAIDSAFE_DHT_LIBRARY} ${CRYPTOPP_LIBRARY} ${UDT_LIBRARY} ${MAIDSAFE_DHT_LIBRARY_DEBUG} ${CRYPTOPP_LIBRARY_DEBUG} ${UDT_LIBRARY_DEBUG})
FOREACH(MAID_LIB ${LIBRARIES_LIST})
  IF(NOT MAID_LIB)
    STRING(REPLACE "-NOTFOUND" "" MLIB ${MAID_LIB})
    SET(ERROR_MESSAGE "\nCould not find ${MLIB}.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download maidsafe-dht at http://code.google.com/p/maidsafe-dht\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If maidsafe-dht is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_LIB_DIR=<Path to maidsafe-dht libraries directory> and/or")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_DHT_ROOT_DIR=<Path to maidsafe-dht root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    MESSAGE("-- Found library ${MAID_LIB}")
  ENDIF()
ENDFOREACH()

SET(MAIDSAFE_DHT_DEPENDENCIES_RELEASE ${UDT_LIBRARY} ${CRYPTOPP_LIBRARY})
LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_RELEASE ${Protobuf_LIBRARY_RELEASE} ${Boost_DATE_TIME_LIBRARY_RELEASE} ${Boost_FILESYSTEM_LIBRARY_RELEASE} ${Boost_REGEX_LIBRARY_RELEASE} ${Boost_SYSTEM_LIBRARY_RELEASE} ${Boost_THREAD_LIBRARY_RELEASE})
IF(MSVC)
  SET(MAIDSAFE_DHT_DEPENDENCIES_DEBUG ${UDT_LIBRARY_DEBUG} ${CRYPTOPP_LIBRARY_DEBUG})
  LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_DEBUG ${Protobuf_LIBRARY_DEBUG} ${Boost_DATE_TIME_LIBRARY_DEBUG} ${Boost_FILESYSTEM_LIBRARY_DEBUG} ${Boost_REGEX_LIBRARY_DEBUG} ${Boost_SYSTEM_LIBRARY_DEBUG} ${Boost_THREAD_LIBRARY_DEBUG})
ENDIF()
IF(Glog_FOUND)
  LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_RELEASE ${Glog_LIBRARY_RELEASE})
  IF(MSVC)
    LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_DEBUG ${Glog_LIBRARY_DEBUG})
  ENDIF()
ENDIF()
IF(UNIX)
  LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_RELEASE dl pthread)
  IF(NOT APPLE)
    LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_RELEASE rt c m)
  ENDIF()
ELSEIF(WIN32)
  IF(MSVC)
    LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_RELEASE ws2_32 odbc32 odbccp32 WSock32 IPHlpApi)
    LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_DEBUG ws2_32 odbc32 odbccp32 WSock32 IPHlpApi)
  ELSE()
    LIST(APPEND MAIDSAFE_DHT_DEPENDENCIES_RELEASE advapi32 kernel32 ws2_32 iphlpapi mswsock)
  ENDIF()
ENDIF()

ADD_LIBRARY(maidsafe_dht_LIBRARY STATIC IMPORTED)
SET_PROPERTY(TARGET maidsafe_dht_LIBRARY APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG MINSIZEREL RELEASE RELWITHDEBINFO)
SET_TARGET_PROPERTIES(maidsafe_dht_LIBRARY PROPERTIES
                        IMPORTED_LINK_INTERFACE_LANGUAGES "C;CXX"
                        IMPORTED_LINK_INTERFACE_LIBRARIES "${MAIDSAFE_DHT_DEPENDENCIES_RELEASE}")
IF(MSVC)
  SET_TARGET_PROPERTIES(maidsafe_dht_LIBRARY PROPERTIES
                          IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG "${MAIDSAFE_DHT_DEPENDENCIES_DEBUG}"
                          IMPORTED_LOCATION "${MAIDSAFE_DHT_LIBRARY}"
                          IMPORTED_LOCATION_DEBUG "${MAIDSAFE_DHT_LIBRARY_DEBUG}")
ELSE()
  SET_TARGET_PROPERTIES(maidsafe_dht_LIBRARY PROPERTIES IMPORTED_LOCATION "${MAIDSAFE_DHT_LIBRARY}")
ENDIF()
