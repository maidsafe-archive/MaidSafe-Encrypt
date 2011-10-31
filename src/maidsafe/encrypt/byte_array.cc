
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

#include "maidsafe/encrypt/byte_array.h"
#include "maidsafe/encrypt/log.h"

namespace maidsafe {
namespace encrypt {

ByteArray GetNewByteArray(const uint32_t &size) {
  ByteArray byte_array(new byte[size], ByteArrayDeleter(size));
  memset(byte_array.get(), 0, size);
  return byte_array;
}

uint32_t Size(const std::shared_ptr<byte> &ptr) {
  return ptr ? std::get_deleter<ByteArrayDeleter>(ptr)->kSize_ : 0;
}

uint32_t MemCopy(const ByteArray &destination,
                 const uint32_t &destination_offset,
                 const void *source,
                 uint32_t copy_size) {
  if (Size(destination) < destination_offset) {
    DLOG(WARNING) << "Size (" << Size(destination) << ") < offset ("
        << destination_offset << ").";
    return 0;
  }
  if (Size(destination) - destination_offset < copy_size) {
    DLOG(WARNING) << "Resizing from " << copy_size << " to "
        << Size(destination) - destination_offset << " to avoid overrun.";
    copy_size = Size(destination) - destination_offset;
  }
  memcpy(destination.get() + destination_offset, source, copy_size);
  return copy_size;
}

}  // namespace encrypt
}  // namespace maidsafe
