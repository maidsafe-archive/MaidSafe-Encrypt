# ============================================================================ #
#                                                                              #
# Copyright [2010] maidsafe.net limited                                        #
#                                                                              #
# Description:  See below.                                                     #
# Version:      1.0                                                            #
# Created:      2010-05-19-09.59.02                                            #
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
#  Written by maidsafe.net team                                                #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Module used to locate Google Logging libs and headers.                      #
#                                                                              #
#  Currently Glog can't be compiled on Windows using MinGW.                    #
#                                                                              #
#  Settable variables to aid with finding Glog are:                            #
#    GLOG_LIB_DIR, GLOG_INC_DIR and GLOG_ROOT_DIR                              #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Glog_INCLUDE_DIR, Glog_LIBRARY_DIR, Glog_LIBRARY, Glog_FOUND              #
#                                                                              #
#  For MSVC, Glog_LIBRARY_DIR_DEBUG and Glog_LIBRARY_DEBUG are also set and    #
#  cached.                                                                     #
#                                                                              #
#==============================================================================#

IF(WIN32 AND NOT MSVC)
  MESSAGE(FATAL_ERROR "\nThis module is only applicable on Windows when building for Microsoft Visual Studio.\n\n")
ENDIF()

UNSET(Glog_INCLUDE_DIR CACHE)
UNSET(Glog_LIBRARY_DIR CACHE)
UNSET(Glog_LIBRARY_DIR_DEBUG CACHE)
UNSET(Glog_LIBRARY CACHE)
UNSET(Glog_LIBRARY_DEBUG CACHE)
UNSET(Glog_FOUND CACHE)

IF(GLOG_LIB_DIR)
  SET(GLOG_LIB_DIR ${GLOG_LIB_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
ENDIF()
IF(GLOG_INC_DIR)
  SET(GLOG_INC_DIR ${GLOG_INC_DIR} CACHE PATH "Path to Google Logging include directory" FORCE)
ENDIF()
IF(GLOG_ROOT_DIR)
  SET(GLOG_ROOT_DIR ${GLOG_ROOT_DIR} CACHE PATH "Path to Google Logging root directory" FORCE)
ENDIF()

IF(MSVC)
  SET(GLOG_LIBPATH_SUFFIX Release)
ELSE()
  SET(GLOG_LIBPATH_SUFFIX lib lib64)
ENDIF()

FIND_LIBRARY(Glog_LIBRARY NAMES libglog.a glog libglog_static PATHS ${GLOG_LIB_DIR} ${GLOG_ROOT_DIR} PATH_SUFFIXES ${GLOG_LIBPATH_SUFFIX})
IF(MSVC)
  SET(GLOG_LIBPATH_SUFFIX Debug)
  FIND_LIBRARY(Glog_LIBRARY_DEBUG NAMES libglog_static PATHS ${GLOG_LIB_DIR} ${GLOG_ROOT_DIR} PATH_SUFFIXES ${GLOG_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Glog_INCLUDE_DIR glog/logging.h PATHS ${GLOG_INC_DIR} ${GLOG_ROOT_DIR}/src/windows)

GET_FILENAME_COMPONENT(GLOG_LIBRARY_DIR ${Glog_LIBRARY} PATH)
SET(Glog_LIBRARY_DIR ${GLOG_LIBRARY_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(GLOG_LIBRARY_DIR_DEBUG ${Glog_LIBRARY_DEBUG} PATH)
  SET(Glog_LIBRARY_DIR_DEBUG ${GLOG_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Logging debug libraries directory" FORCE)
ENDIF()


IF(NOT Glog_LIBRARY)
  SET(WARNING_MESSAGE TRUE)
  MESSAGE("-- Did not find Google Logging library")
ELSE()
  MESSAGE("-- Found Google Logging library")
ENDIF()

IF(MSVC)
  IF(NOT Glog_LIBRARY_DEBUG)
    SET(WARNING_MESSAGE TRUE)
    MESSAGE("-- Did not find Google Logging Debug library")
  ELSE()
    MESSAGE("-- Found Google Logging Debug library")
  ENDIF()
ENDIF()

IF(NOT Glog_INCLUDE_DIR)
  SET(WARNING_MESSAGE TRUE)
  MESSAGE("-- Did not find Google Logging library headers")
ENDIF()

IF(WARNING_MESSAGE)
  SET(WARNING_MESSAGE "   You can download it at http://code.google.com/p/google-glog\n")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}   If Google Logging is already installed, run:\n")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}   ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_LIB_DIR=<Path to glog lib directory> and/or")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n   ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_INC_DIR=<Path to glog include directory> and/or")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n   ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>")
  MESSAGE("${WARNING_MESSAGE}")
  SET(Glog_FOUND FALSE CACHE INTERNAL "Found Google Logging library and headers" FORCE)
  UNSET(Glog_INCLUDE_DIR CACHE)
  UNSET(Glog_LIBRARY_DIR CACHE)
  UNSET(Glog_LIBRARY_DIR_DEBUG CACHE)
  UNSET(Glog_LIBRARY CACHE)
  UNSET(Glog_LIBRARY_DEBUG CACHE)
ELSE()
  SET(Glog_FOUND TRUE CACHE INTERNAL "Found Google Logging library and headers" FORCE)
ENDIF()

