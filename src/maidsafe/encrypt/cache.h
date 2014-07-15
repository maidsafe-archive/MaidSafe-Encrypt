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

#ifndef MAIDSAFE_ENCRYPT_CACHE_H_
#define MAIDSAFE_ENCRYPT_CACHE_H_

#include <cstdint>
#include <memory>
#include <vector>
#include <mutex>
#include "maidsafe/common/config.h"

namespace maidsafe {

namespace encrypt {

class Cache {
 public:
  Cache(uint32_t max_size = kMaxChunkSize * 8);
  ~Cache() = default;
  Cache(const Cache& other) = delete;
  Cache(const Cache&& other) = delete;
  Cache operator=(Cache other) = delete;
  void Put(std::vector<char> data, uint64_t file_position);
  bool Get(std::vector<char>& data, uint32_t length, uint64_t file_position) const;
  // bool InCache(uint32_t length, uint64_t file_position) const;
  // uint64_t StartPosition() const;
  // uint64_t EndPosition() const;
  // bool Size() const;
  // bool Full() const;

 private:
  mutable std::mutex mutex_;
  std::vector<char> cache_;
  uint32_t max_size_;
  uint64_t start_;
  // uint64_t end_;
};


}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CACHE_H_
