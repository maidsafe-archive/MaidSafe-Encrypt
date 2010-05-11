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
#  Module used to locate SQLite3 libs and header for use in MSVC builds        #
#                                                                              #
#  Settable variable to aid with finding SQLite3 is SQLITE3_ROOT_DIR           #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Sqlite3_INCLUDE_DIR, Sqlite3_LIBRARY_DIR, Sqlite3_LIBRARY_DIR_DEBUG,      #
#    Sqlite3_LIBRARY, and Sqlite3_LIBRARY_DEBUG.                               #
#                                                                              #
#==============================================================================#

IF(NOT MSVC)
  MESSAGE(FATAL_ERROR "\nThis module is only applicable when building for Microsoft Visual Studio.\n\n")
ENDIF()

UNSET(Sqlite3_INCLUDE_DIR CACHE)
UNSET(Sqlite3_LIBRARY_DIR CACHE)
UNSET(Sqlite3_LIBRARY_DIR_DEBUG CACHE)
UNSET(Sqlite3_LIBRARY CACHE)
UNSET(Sqlite3_LIBRARY_DEBUG CACHE)

IF(SQLITE3_ROOT_DIR)
  SET(SQLITE3_ROOT_DIR ${SQLITE3_ROOT_DIR} CACHE PATH "Path to SQLite3 root directory" FORCE)
ENDIF()

FIND_LIBRARY(Sqlite3_LIBRARY NAMES SQLite3 PATHS ${SQLITE3_ROOT_DIR} PATH_SUFFIXES Release)
FIND_LIBRARY(Sqlite3_LIBRARY_DEBUG NAMES SQLite3 PATHS ${SQLITE3_ROOT_DIR} PATH_SUFFIXES Debug)

FIND_PATH(Sqlite3_INCLUDE_DIR sqlite3.h PATHS ${SQLITE3_ROOT_DIR}/SQLite3)

GET_FILENAME_COMPONENT(SQLITE3_LIBRARY_DIR ${Sqlite3_LIBRARY} PATH)
SET(Sqlite3_LIBRARY_DIR ${SQLITE3_LIBRARY_DIR} CACHE PATH "Path to SQLite3 library directory" FORCE)
GET_FILENAME_COMPONENT(SQLITE3_LIBRARY_DIR_DEBUG ${Sqlite3_LIBRARY_DEBUG} PATH)
SET(Sqlite3_LIBRARY_DIR_DEBUG ${SQLITE3_LIBRARY_DIR_DEBUG} CACHE PATH "Path to SQLite3 Debug library directory" FORCE)

IF(NOT Sqlite3_LIBRARY)
  SET(ERROR_MESSAGE "\nCould not find SQLite3.  NO SQLITE3 LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If SQLite3 is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DSQLITE3_ROOT_DIR=<Path to SQLite3 root directory>\n")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

IF(NOT Sqlite3_LIBRARY_DEBUG)
  SET(ERROR_MESSAGE "\nCould not find SQLite3.  NO *DEBUG* SQLITE3 LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If SQLite3 is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DSQLITE3_ROOT_DIR=<Path to SQLite3 root directory>\n")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

IF(NOT Sqlite3_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find SQLite3.  NO SQLITE3.H - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If SQLite3 is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DSQLITE3_ROOT_DIR=<Path to SQLite3 root directory>\n")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

MESSAGE("-- Found SQLite3 library")
MESSAGE("-- Found SQLite3 Debug library")
