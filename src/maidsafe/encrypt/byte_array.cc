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

#include "maidsafe/encrypt/byte_array.h"
#include "maidsafe/common/log.h"

namespace maidsafe {
namespace encrypt {

ByteArray GetNewByteArray(const uint32_t &size) {
  ByteArray byte_array(new byte[size], ByteArrayDeleter(size));
  memset(byte_array.get(), 0, size);
  return std::move(byte_array);
}

uint32_t Size(const std::shared_ptr<byte> &ptr) {
  return ptr ? std::get_deleter<ByteArrayDeleter>(ptr)->kSize_ : 0;
}

uint32_t MemCopy(const ByteArray &destination,
                 const uint32_t &destination_offset,
                 const void *source,
                 uint32_t copy_size) {
  if (Size(destination) < destination_offset) {
    LOG(kWarning) << "Size (" << Size(destination) << ") < offset ("
        << destination_offset << ").";
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
