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
#  Module used to locate Google Breakpad lib and header.                       #
#                                                                              #
#  Settable variables to aid with finding Breakpad are:                        #
#    BREAKPAD_LIB_DIR, BREAKPAD_INC_DIR and BREAKPAD_ROOT_DIR                  #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Breakpad_INCLUDE_DIR, Breakpad_LIBRARY_DIR, Breakpad_LIBRARY              #
#                                                                              #
#  For MSVC, Breakpad_LIBRARY_DIR_DEBUG is also set and cached.                #
#                                                                              #
#==============================================================================#


UNSET(Breakpad_INCLUDE_DIR CACHE)
UNSET(Breakpad_LIBRARY_DIR CACHE)
UNSET(Breakpad_LIBRARY_DIR_DEBUG CACHE)
UNSET(Breakpad_LIBRARY CACHE)
UNSET(Breakpad_LIBRARY_DEBUG CACHE)
UNSET(Breakpad_LIBRARY_RELEASE CACHE)

IF(BREAKPAD_LIB_DIR)
  SET(BREAKPAD_LIB_DIR ${BREAKPAD_LIB_DIR} CACHE INTERNAL "Path to Breakpad library directory" FORCE)
ENDIF()
IF(BREAKPAD_INC_DIR)
  SET(BREAKPAD_INC_DIR ${BREAKPAD_INC_DIR} CACHE INTERNAL "Path to Breakpad include directory" FORCE)
ENDIF()
IF(BREAKPAD_ROOT_DIR)
  SET(BREAKPAD_ROOT_DIR ${BREAKPAD_ROOT_DIR} CACHE INTERNAL "Path to Breakpad root directory" FORCE)
ELSEIF(DEFAULT_THIRD_PARTY_ROOT)
  FIND_THIRD_PARTY_PROJECT(BREAKPAD_ROOT_DIR google-breakpad ${DEFAULT_THIRD_PARTY_ROOT})
  IF(BREAKPAD_ROOT_DIR_CACHED)
    SET(BREAKPAD_ROOT_DIR ${BREAKPAD_ROOT_DIR_CACHED})
  ENDIF()
ENDIF()

IF(MSVC)
  SET(BREAKPAD_LIBPATH_SUFFIX src/client/windows/Release)
ELSE()
  SET(BREAKPAD_LIBPATH_SUFFIX src/.libs)
ENDIF()

FIND_LIBRARY(Breakpad_LIBRARY_RELEASE NAMES libbreakpad_client.a exception_handler PATHS ${BREAKPAD_LIB_DIR} ${BREAKPAD_ROOT_DIR} PATH_SUFFIXES ${BREAKPAD_LIBPATH_SUFFIX})
IF(MSVC)
  SET(BREAKPAD_LIBPATH_SUFFIX src/client/windows/Debug)
  FIND_LIBRARY(Breakpad_LIBRARY_DEBUG NAMES exception_handler PATHS ${BREAKPAD_LIB_DIR} ${BREAKPAD_ROOT_DIR} PATH_SUFFIXES ${BREAKPAD_LIBPATH_SUFFIX})
ENDIF()

IF(MSVC)
  FIND_PATH(Breakpad_INCLUDE_DIR client/windows/handler/exception_handler.h PATHS ${BREAKPAD_INC_DIR} ${BREAKPAD_ROOT_DIR} PATH_SUFFIXES src/)
ELSE(UNIX AND NOT APPLE)
  FIND_PATH(Breakpad_INCLUDE_DIR client/linux/handler/exception_handler.h PATHS ${BREAKPAD_INC_DIR} ${BREAKPAD_ROOT_DIR} PATH_SUFFIXES google/breakpad/ src/)
ELSE(APPLE)
  FIND_PATH(Breakpad_INCLUDE_DIR client/mac/handler/exception_handler.h PATHS ${BREAKPAD_INC_DIR} ${BREAKPAD_ROOT_DIR} PATH_SUFFIXES google/breakpad/ src/)
ENDIF()

GET_FILENAME_COMPONENT(BREAKPAD_LIBRARY_DIR ${Breakpad_LIBRARY_RELEASE} PATH)
SET(Breakpad_LIBRARY_DIR ${BREAKPAD_LIBRARY_DIR} CACHE PATH "Path to Google Breakpad libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(BREAKPAD_LIBRARY_DIR_DEBUG ${Breakpad_LIBRARY_DEBUG} PATH)
  SET(Breakpad_LIBRARY_DIR_DEBUG ${BREAKPAD_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Breakpad debug libraries directory" FORCE)
ENDIF()

IF(NOT Breakpad_LIBRARY_RELEASE)
  SET(ERROR_MESSAGE "\nCould not find Google Breakpad.  NO BREAKPAD LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-breakpad\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Breakpad is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DBREAKPAD_LIB_DIR=<Path to Breakpad lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\ncmake ../.. -DBREAKPAD_ROOT_DIR=<Path to Breakpad root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Breakpad_LIBRARY ${Breakpad_LIBRARY_RELEASE} CACHE PATH "Path to Google Breakpad library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT Breakpad_LIBRARY_DEBUG)
    SET(ERROR_MESSAGE "\nCould not find Google Breakpad.  NO *DEBUG* BREAKPAD LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-breakpad\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Breakpad is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DBREAKPAD_LIB_DIR=<Path to Breakpad lib directory> and/or")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}\ncmake ../.. -DBREAKPAD_ROOT_DIR=<Path to Breakpad root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(Breakpad_LIBRARY debug ${Breakpad_LIBRARY_DEBUG} optimized ${Breakpad_LIBRARY} CACHE PATH "Path to Google Breakpad libraries" FORCE)
  ENDIF()
ENDIF()

IF(NOT Breakpad_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find Google Breakpad.  NO EXCEPTION_HANDLER.H - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-breakpad\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Breakpad is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DBREAKPAD_INC_DIR=<Path to Breakpad include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\ncmake ../.. -DBREAKPAD_ROOT_DIR=<Path to Breakpad root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

MESSAGE("-- Found Google Breakpad library")
IF(MSVC)
  MESSAGE("-- Found Google Breakpad Debug library")
ENDIF()
