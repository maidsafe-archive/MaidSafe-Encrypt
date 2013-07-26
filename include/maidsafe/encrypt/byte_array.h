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

#ifndef MAIDSAFE_ENCRYPT_BYTE_ARRAY_H_
#define MAIDSAFE_ENCRYPT_BYTE_ARRAY_H_

#include <cstdint>
#include <memory>
#include "cryptopp/config.h"

namespace maidsafe {
namespace encrypt {

typedef std::shared_ptr<byte> ByteArray;

ByteArray GetNewByteArray(const uint32_t &size);

uint32_t Size(const ByteArray &ptr);

uint32_t MemCopy(const ByteArray &destination,
                 const uint32_t &destination_offset,
                 const void *source,
                 uint32_t copy_size);

struct ByteArrayDeleter {
  explicit ByteArrayDeleter(const uint32_t &size) : kSize_(size) {}
  void operator() (byte *&ptr) {
    delete[] ptr;
    ptr = nullptr;
  }
  const uint32_t kSize_;
};


}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_BYTE_ARRAY_H_
