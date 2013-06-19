
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


namespace maidsafe {

namespace encrypt {

const uint32_t kMinChunkSize(1024);  // bytes
const uint32_t kDefaultChunkSize(1024 * 1024);  // bytes

enum ReturnCode {
  kSuccess = 0,
  kInvalidChunkIndex = -200001,
  kFailedToStoreChunk = -200002,
  kMissingChunk = -200003,
  kEncryptionException = -200004,
  kDecryptionException = -200005,
  kInvalidPosition = -200006,
  kSequencerException = -200007,
  kSequencerAddError = -200008
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CONFIG_H_
