
/*******************************************************************************
*  Copyright 2011 MaidSafe.net limited                                         *
*                                                                              *
*  The following source code is property of MaidSafe.net limited and is not    *
*  meant for external use.  The use of this code is governed by the license    *
*  file LICENSE.TXT found in the root of this directory and also on            *
*  www.MaidSafe.net.                                                           *
*                                                                              *
*  You are not free to copy, amend or otherwise use this source code without   *
*  the explicit written permission of the board of directors of MaidSafe.net.  *
*******************************************************************************/

#ifndef MAIDSAFE_ENCRYPT_VERSION_H_
#define MAIDSAFE_ENCRYPT_VERSION_H_

#define MAIDSAFE_ENCRYPT_VERSION 1100

#if defined CMAKE_MAIDSAFE_ENCRYPT_VERSION &&\
            MAIDSAFE_ENCRYPT_VERSION != CMAKE_MAIDSAFE_ENCRYPT_VERSION
#  error The project version has changed.  Re-run CMake.
#endif

#include "maidsafe/common/version.h"

#define THIS_NEEDS_MAIDSAFE_COMMON_VERSION 1100
#if MAIDSAFE_COMMON_VERSION < THIS_NEEDS_MAIDSAFE_COMMON_VERSION
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-common library.
#elif MAIDSAFE_COMMON_VERSION > THIS_NEEDS_MAIDSAFE_COMMON_VERSION
#  error This API uses a newer version of the maidsafe-common library.\
    Please update this project.
#endif

#include "maidsafe/private/version.h"

#define THIS_NEEDS_MAIDSAFE_PRIVATE_VERSION 200
#if MAIDSAFE_PRIVATE_VERSION < THIS_NEEDS_MAIDSAFE_PRIVATE_VERSION
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-private library.
#elif MAIDSAFE_PRIVATE_VERSION > THIS_NEEDS_MAIDSAFE_PRIVATE_VERSION
#  error This API uses a newer version of the maidsafe-private library.\
    Please update this project.
#endif

#endif  // MAIDSAFE_ENCRYPT_VERSION_H_
