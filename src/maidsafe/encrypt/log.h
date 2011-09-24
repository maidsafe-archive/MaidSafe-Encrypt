
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

#ifndef MAIDSAFE_ENCRYPT_LOG_H_
#define MAIDSAFE_ENCRYPT_LOG_H_

#include "maidsafe/common/log.h"

#undef LOG
#define LOG(severity) COMPACT_GOOGLE_LOG_ ## severity(encrypt, :).stream()

#endif  // MAIDSAFE_ENCRYPT_LOG_H_
