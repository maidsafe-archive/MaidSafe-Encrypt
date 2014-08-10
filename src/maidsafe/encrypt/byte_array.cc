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

#include "maidsafe/encrypt/byte_array.h"
#include "maidsafe/common/log.h"

namespace maidsafe {

namespace encrypt {

ByteArray GetNewByteArray(uint32_t size) {
  ByteArray byte_array(new byte[size], ByteArrayDeleter(size));
  memset(byte_array.get(), 0, size);
  return std::move(byte_array);
}

uint32_t Size(const std::shared_ptr<byte>& ptr) {
  return ptr ? std::get_deleter<ByteArrayDeleter>(ptr)->kSize_ : 0;
}

uint32_t MemCopy(const ByteArray& destination, uint32_t destination_offset, const void* source,
                 uint32_t copy_size) {
  if (Size(destination) < destination_offset) {
    LOG(kWarning) << "Size (" << Size(destination) << ") < offset (" << destination_offset << ").";
    return 0;
  }
  if (Size(destination) - destination_offset < copy_size) {
    LOG(kWarning) << "Resizing from " << copy_size << " to "
                  << Size(destination) - destination_offset << " to avoid overrun.";
    copy_size = Size(destination) - destination_offset;
  }
  memcpy(destination.get() + destination_offset, source, copy_size);
  return copy_size;
}

}  // namespace encrypt

}  // namespace maidsafe
