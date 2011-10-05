
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

#ifndef MAIDSAFE_ENCRYPT_CONFIG_H_
#define MAIDSAFE_ENCRYPT_CONFIG_H_

#include <cstdint>

#include "maidsafe/encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION != 1000
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-encrypt library.
#endif

namespace maidsafe {
namespace encrypt {

const uint32_t kMinChunkSize(1024);  // bytes
const uint32_t kDefaultChunkSize(1024 * 256);  // bytes

enum ReturnCode {
  kSuccess = 0,
  kEncryptError = -200001,
  kDecryptError = -200002,
  kInvalidChunkIndex = -200003,
  kFailedToStoreChunk = -200004,
  kMissingChunk = -200005,
  kEncryptionException = -200006,
  kDecryptionException = -200007,
  kInvalidPosition = -200008,
  kSequencerException = -200101,
  kSequencerAddError = -200102
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CONFIG_H_
