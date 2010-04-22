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
#  Module used to locate BitRock InstallBuilder executables.                   #
#                                                                              #
#  Settable variable to aid with finding InstallBuilder is:                    #
#    INSTALLBUILDER_ROOT_DIR                                                   #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    InstallBuilder_BUILDER_EXE and InstallBuilder_CUSTOMISE_EXE               #
#                                                                              #
#==============================================================================#


UNSET(InstallBuilder_BUILDER_EXE CACHE)
UNSET(InstallBuilder_CUSTOMISE_EXE CACHE)

SET(INSTALLBUILDER_REQUIRED TRUE)
IF(INSTALLBUILDER_ROOT_DIR)
  IF(INSTALLBUILDER_ROOT_DIR MATCHES NA)
    SET(INSTALLBUILDER_REQUIRED FALSE)
  ELSE()
    SET(INSTALLBUILDER_ROOT_DIR ${INSTALLBUILDER_ROOT_DIR} CACHE INTERNAL "Path to BitRock InstallBuilder root directory" FORCE)
  ENDIF()
ENDIF()

IF(INSTALLBUILDER_REQUIRED)
  SET(BUILDER_SUFFIX bin)
  SET(CUSTOMISE_SUFFIX autoupdate/bin)
  IF(WIN32)
    FIND_FILE(InstallBuilder_BUILDER_EXE NAMES builder.exe PATHS ${INSTALLBUILDER_ROOT_DIR} PATH_SUFFIXES ${BUILDER_SUFFIX})
    FIND_FILE(InstallBuilder_CUSTOMISE_EXE NAMES customize.exe PATHS ${INSTALLBUILDER_ROOT_DIR} PATH_SUFFIXES ${CUSTOMISE_SUFFIX})
  ELSEIF(APPLE)
    SET(BUILDER_SUFFIX bin/Builder.app/Contents/MacOS)
    SET(CUSTOMISE_SUFFIX autoupdate/bin/.customize.app/Contents/MacOS)
    FIND_FILE(InstallBuilder_BUILDER_EXE NAMES installbuilder.sh PATHS ${INSTALLBUILDER_ROOT_DIR} PATH_SUFFIXES ${BUILDER_SUFFIX})
    FIND_FILE(InstallBuilder_CUSTOMISE_EXE NAMES installbuilder.sh PATHS ${INSTALLBUILDER_ROOT_DIR} PATH_SUFFIXES ${CUSTOMISE_SUFFIX})
  ELSE()
    FIND_FILE(InstallBuilder_BUILDER_EXE NAMES builder PATHS ${INSTALLBUILDER_ROOT_DIR} PATH_SUFFIXES ${BUILDER_SUFFIX})
    FIND_FILE(InstallBuilder_CUSTOMISE_EXE NAMES customize.bin PATHS ${INSTALLBUILDER_ROOT_DIR} PATH_SUFFIXES ${CUSTOMISE_SUFFIX})
  ENDIF()

  IF(NOT InstallBuilder_BUILDER_EXE)
    SET(ERROR_MESSAGE "\nCould not find BitRock InstallBuilder builder executable.\n\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If InstallBuilder is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DINSTALLBUILDER_ROOT_DIR=<Path to BitRock InstallBuilder root directory>\n\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If InstallBuilder is not required, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DINSTALLBUILDER_ROOT_DIR=NA\n\n")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()

  IF(NOT InstallBuilder_CUSTOMISE_EXE)
    SET(ERROR_MESSAGE "\nCould not find BitRock InstallBuilder customize executable.\n\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If InstallBuilder is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DINSTALLBUILDER_ROOT_DIR=<Path to BitRock InstallBuilder root directory>\n\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If InstallBuilder is not required, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}cmake ../.. -DINSTALLBUILDER_ROOT_DIR=NA\n\n")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ENDIF()
