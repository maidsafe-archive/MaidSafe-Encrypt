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
#  Module used to locate Google Protocol Buffers libs, headers & compiler and  #
#  run protoc against PD .proto files if their contents have changed or if     #
#  protobuf version has changed.                                               #
#                                                                              #
#  Settable variables to aid with finding protobuf and protoc are:             #
#    PROTOBUF_LIB_DIR, PROTOBUF_INC_DIR, PROTOC_EXE_DIR and PROTOBUF_ROOT_DIR  #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Protobuf_INCLUDE_DIR, Protobuf_LIBRARY_DIR, Protobuf_LIBRARY and          #
#    Protobuf_PROTOC_EXECUTABLE                                                #
#                                                                              #
#  For MSVC, Protobuf_LIBRARY_DIR_DEBUG and Protobuf_LIBRARY_DEBUG are also    #
#  set and cached.                                                             #
#                                                                              #
#==============================================================================#


#Function to generate CC and header files derived from proto files
FUNCTION(GENERATE_PROTO_FILES PROTO_FILE CACHE_NAME)
  FILE(STRINGS ${${PROJECT_NAME}_SOURCE_DIR}/${PROTO_FILE} PROTO_STRING)
  UNSET(NEW_${ARGV1} CACHE)
  SET(NEW_${ARGV1} ${PROTO_STRING} CACHE STRING "Google Protocol Buffers - new file contents for ${ARGV1}")
  IF((${FORCE_PROTOC_COMPILE}) OR (NOT "${NEW_${ARGV1}}" STREQUAL "${${ARGV1}}"))
    GET_FILENAME_COMPONENT(PROTO_FILE_NAME ${${PROJECT_NAME}_SOURCE_DIR}/${PROTO_FILE} NAME)
    EXECUTE_PROCESS(COMMAND ${Protobuf_PROTOC_EXECUTABLE}
                      --proto_path=${${PROJECT_NAME}_SOURCE_DIR}
                      --cpp_out=${${PROJECT_NAME}_SOURCE_DIR}
                      ${${PROJECT_NAME}_SOURCE_DIR}/${PROTO_FILE}
                      RESULT_VARIABLE PROTO_RES
                      ERROR_VARIABLE PROTO_ERR)
    UNSET(${ARGV1} CACHE)
    IF(NOT ${PROTO_RES})
      MESSAGE("--   Generated files from ${PROTO_FILE_NAME}")
      SET(${ARGV1} ${PROTO_STRING} CACHE STRING "Google Protocol Buffers - file contents for ${PROTO_FILE}")
    ELSE()
      MESSAGE(FATAL_ERROR "Failed trying to generate files from ${PROTO_FILE_NAME}\n${PROTO_ERR}")
    ENDIF()
  ENDIF()
  UNSET(NEW_${ARGV1} CACHE)
ENDFUNCTION()


UNSET(Protobuf_INCLUDE_DIR CACHE)
UNSET(Protobuf_LIBRARY_DIR CACHE)
UNSET(Protobuf_LIBRARY CACHE)
UNSET(Protobuf_LIBRARY_DIR_DEBUG CACHE)
UNSET(Protobuf_LIBRARY_DEBUG CACHE)
UNSET(Protobuf_PROTOC_EXECUTABLE CACHE)
UNSET(PROTOBUF_LIBRARY_RELEASE CACHE)
UNSET(PROTOBUF_LIBRARY_DEBUG CACHE)
UNSET(PROTOC_EXE_RELEASE CACHE)

IF(PROTOBUF_LIB_DIR)
  SET(PROTOBUF_LIB_DIR ${PROTOBUF_LIB_DIR} CACHE INTERNAL "Path to Google Protocol Buffers libraries directory" FORCE)
ENDIF()
IF(PROTOBUF_INC_DIR)
  SET(PROTOBUF_INC_DIR ${PROTOBUF_INC_DIR} CACHE INTERNAL "Path to Google Protocol Buffers include directory" FORCE)
ENDIF()
IF(PROTOC_EXE_DIR)
  SET(PROTOC_EXE_DIR ${PROTOC_EXE_DIR} CACHE INTERNAL "Path to Google Protocol Buffers executable (protoc) directory" FORCE)
ENDIF()
IF(PROTOBUF_ROOT_DIR)
  SET(PROTOBUF_ROOT_DIR ${PROTOBUF_ROOT_DIR} CACHE INTERNAL "Path to Google Protocol Buffers root directory" FORCE)
ELSEIF(DEFAULT_THIRD_PARTY_ROOT)
  FIND_THIRD_PARTY_PROJECT(PROTOBUF_ROOT_DIR protobuf ${DEFAULT_THIRD_PARTY_ROOT})
  IF(PROTOBUF_ROOT_DIR_CACHED)
    SET(PROTOBUF_ROOT_DIR ${PROTOBUF_ROOT_DIR_CACHED})
  ENDIF()
ENDIF()

IF(MSVC)
  SET(PROTOBUF_LIBPATH_SUFFIX vsprojects/Release)
ELSE()
  SET(PROTOBUF_LIBPATH_SUFFIX lib)
ENDIF()

FIND_LIBRARY(PROTOBUF_LIBRARY_RELEASE NAMES protobuf libprotobuf PATHS ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
FIND_PROGRAM(PROTOC_EXE_RELEASE NAMES protoc PATHS ${PROTOC_EXE_DIR} ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
IF(MSVC)
  SET(PROTOBUF_LIBPATH_SUFFIX vsprojects/Debug)
  FIND_LIBRARY(PROTOBUF_LIBRARY_DEBUG NAMES libprotobuf PATHS ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Protobuf_INCLUDE_DIR google/protobuf/service.h PATHS ${PROTOBUF_INC_DIR} ${PROTOBUF_ROOT_DIR}/src)

GET_FILENAME_COMPONENT(PROTOBUF_LIBRARY_DIR ${PROTOBUF_LIBRARY_RELEASE} PATH)
SET(Protobuf_LIBRARY_DIR ${PROTOBUF_LIBRARY_DIR} CACHE PATH "Path to Google Protocol Buffers libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(PROTOBUF_LIBRARY_DIR_DEBUG ${PROTOBUF_LIBRARY_DEBUG} PATH)
  SET(Protobuf_LIBRARY_DIR_DEBUG ${PROTOBUF_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Protocol Buffers debug libraries directory" FORCE)
ENDIF()

IF(NOT PROTOBUF_LIBRARY_RELEASE)
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO PROTOBUF LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DPROTOBUF_LIB_DIR=<Path to protobuf lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\ncmake ../.. -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Protobuf_LIBRARY ${PROTOBUF_LIBRARY_RELEASE} CACHE INTERNAL "Path to Google Protocol Buffers library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT PROTOBUF_LIBRARY_DEBUG)
    SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO *DEBUG* PROTOBUF LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(Protobuf_LIBRARY_DEBUG ${PROTOBUF_LIBRARY_DEBUG} CACHE INTERNAL "Path to Google Protocol Buffers debug library" FORCE)
  ENDIF()
ENDIF()

IF(NOT Protobuf_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO HEADER FILE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DPROTOBUF_INC_DIR=<Path to protobuf include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\ncmake ../.. -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

IF(NOT PROTOC_EXE_RELEASE)
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO PROTOC EXE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DPROTOC_EXE_DIR=<Path to protoc directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\ncmake ../.. -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Protobuf_PROTOC_EXECUTABLE ${PROTOC_EXE_RELEASE} CACHE INTERNAL "Path to Google Protocol Buffers executable (protoc) directory" FORCE)
ENDIF()

EXECUTE_PROCESS(COMMAND ${Protobuf_PROTOC_EXECUTABLE} "--version" OUTPUT_VARIABLE TMP_CURRENT_PROTOC_VERSION)
STRING(STRIP ${TMP_CURRENT_PROTOC_VERSION} CURRENT_PROTOC_VERSION)

MESSAGE("-- Found Google Protocol Buffers library")
IF(MSVC)
  MESSAGE("-- Found Google Protocol Buffers Debug library")
ENDIF()

FOREACH(PROTO_FILE ${PROTO_FILES})
  STRING(REGEX REPLACE "[\\/.]" "_" PROTO_CACHE_NAME ${PROTO_FILE})
  GENERATE_PROTO_FILES(${PROTO_FILE} ${PROTO_CACHE_NAME})
ENDFOREACH()



