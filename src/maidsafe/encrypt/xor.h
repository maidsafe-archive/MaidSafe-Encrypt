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

#ifndef MAIDSAFE_ENCRYPT_XOR_H_
#define MAIDSAFE_ENCRYPT_XOR_H_

#ifdef MAIDSAFE_OMP_ENABLED
#include <omp.h>
#endif


#ifdef __MSVC__
#pragma warning(push, 1)
#endif
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#ifdef __MSVC__
#pragma warning(pop)
#endif


namespace maidsafe {

namespace encrypt {

const size_t kPadSize((3 * crypto::SHA512::DIGESTSIZE) - crypto::AES256_KeySize -
                      crypto::AES256_IVSize);

class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  XORFilter(CryptoPP::BufferedTransformation* attachment, byte* pad, size_t pad_size = kPadSize)
      : pad_(pad), count_(0), kPadSize_(pad_size) {
    CryptoPP::Filter::Detach(attachment);
  }
  XORFilter& operator=(const XORFilter&) = delete;
  XORFilter(const XORFilter&) = delete;

  size_t Put2(const byte* in_string, size_t length, int message_end, bool blocking) override {
    if (length == 0) {
      return AttachedTransformation()->Put2(in_string, length, message_end, blocking);
    }
    std::unique_ptr<byte[]> buffer(new byte[length]);

    size_t i(0);
    for (; i != length; ++i) {
      buffer[i] = in_string[i] ^ pad_[count_ % kPadSize_];
      ++count_;
    }

    return AttachedTransformation()->Put2(buffer.get(), length, message_end, blocking);
  }
  bool IsolatedFlush(bool, bool) override { return false; }

 private:
  byte* pad_;
  size_t count_;
  const size_t kPadSize_;
};
}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_XOR_H_
