/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

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
