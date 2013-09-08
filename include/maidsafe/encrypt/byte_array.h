/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

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
