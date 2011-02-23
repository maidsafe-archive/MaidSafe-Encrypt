/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  self_encryption.h
 * @brief Local version definition and DHT version check.
 * @date  2011-01-31
 */

#ifndef MAIDSAFE_ENCRYPT_VERSION_H_
#define MAIDSAFE_ENCRYPT_VERSION_H_

#define MAIDSAFE_ENCRYPT_VERSION 3

#include "maidsafe-dht/common/version.h"

#define THIS_MAIDSAFE_DHT_VERSION 25
#if MAIDSAFE_DHT_VERSION < THIS_MAIDSAFE_DHT_VERSION
#error This API is not compatible with the installed library.\
  Please update the maidsafe-dht library.
#elif MAIDSAFE_DHT_VERSION > THIS_MAIDSAFE_DHT_VERSION
#error This API uses a newer version of the maidsafe-dht library.\
  Please update this project.
#endif

#endif  // MAIDSAFE_ENCRYPT_VERSION_H_
