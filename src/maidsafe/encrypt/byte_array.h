
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
    ptr = NULL;
  }
  const uint32_t kSize_;
};


}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_BYTE_ARRAY_H_
