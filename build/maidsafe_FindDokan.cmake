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
#  Module used to locate Dokan lib and header.                                 #
#                                                                              #
#  Settable variables to aid with finding Dokan are:                           #
#    DOKAN_LIB_DIR and DOKAN_INC_DIR                                           #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Dokan_INCLUDE_DIR, Dokan_LIBRARY_DIR, Dokan_LIBRARY                       #
#                                                                              #
#==============================================================================#


UNSET(Dokan_INCLUDE_DIR CACHE)
UNSET(Dokan_LIBRARY_DIR CACHE)
UNSET(Dokan_LIBRARY CACHE)

IF(DOKAN_LIB_DIR)
  SET(DOKAN_LIB_DIR ${DOKAN_LIB_DIR} CACHE INTERNAL "Path to Dokan library directory" FORCE)
ENDIF()
FIND_LIBRARY(Dokan_LIBRARY NAMES dokan dokan.lib PATHS ${DOKAN_LIB_DIR})
IF(NOT Dokan_LIBRARY)
  SET(ERROR_MESSAGE "\nCould not find Dokan.  NO DOKAN LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Dokan is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DDOKAN_LIB_DIR=<Path to Dokan lib directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()
GET_FILENAME_COMPONENT(DOKAN_LIB_DIR ${Dokan_LIBRARY} PATH)
SET(Dokan_LIBRARY_DIR ${DOKAN_LIB_DIR} CACHE PATH "Path to Dokan library directory" FORCE)

IF(DOKAN_INC_DIR)
  SET(DOKAN_INC_DIR ${DOKAN_INC_DIR} CACHE INTERNAL "Path to Dokan include directory" FORCE)
ENDIF()
FIND_PATH(Dokan_INCLUDE_DIR dokan.h PATHS ${DOKAN_INC_DIR})
IF(NOT Dokan_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find Dokan.  NO DOKAN.H - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Dokan is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DDOKAN_INC_DIR=<Path to Dokan include directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

MESSAGE("-- Found library ${Dokan_LIBRARY}")
