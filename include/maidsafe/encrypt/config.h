/* Copyright 2011 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
