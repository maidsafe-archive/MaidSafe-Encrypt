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

/*############################################ Documentation ######################################
This is a simple cache for encrypt library only. It is based on vectors of chars and not intended
for any other types. It may be templated easily enough though as most fundamental types should be
ok.
The purpose is to be used as a cache, therefore mostly when a read is requested it will be a cache
hit, but not every read. If this object works properly and 80% plus reads are cache hits then it is
considered to be doing its job. It is intentionally pretty dumb and based on a simple design.

--------------------------------------------
^            ^                              ^
cache_start_position_       Insertion point               end (cache_.size())

If data is put here if at least the position it requests in the cache, or the position plus length
will put the data in the cache (so a request for a position < cache_start_position_ but where
position + length
puts it in the cache) The object is optimised fro forward reading cache operations, which may prove
to be a liability. A double ended cache object (list/deque etc.) has been tested and is
considerably slower (certainly in our tests and benchmarks), so this choice will have to be made
with that in mind. As is this cache seems to provide the functionality we require.
*/

#ifndef MAIDSAFE_ENCRYPT_CACHE_H_
#define MAIDSAFE_ENCRYPT_CACHE_H_

#include <cstdint>
#include <memory>
#include <vector>
#include <mutex>
#include "maidsafe/common/config.h"

namespace maidsafe {

namespace encrypt {
using byte = unsigned char;
class Cache {
 public:
  explicit Cache(uint32_t max_size = kMaxChunkSize * 8);
  ~Cache() = default;
  Cache(const Cache& other) = delete;
  Cache(const Cache&& other) = delete;
  Cache operator=(Cache other) = delete;
  void Put(std::vector<byte> data, uint64_t file_position);
  bool Get(std::vector<byte>& data, uint32_t length, uint64_t file_position) const;

 private:
  mutable std::mutex mutex_;
  std::vector<byte> cache_;
  uint32_t max_size_;
  uint64_t cache_start_position_;
};


}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CACHE_H_
