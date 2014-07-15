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
#include "maidsafe/encrypt/cache.h"
#include <cstdint>
#include <memory>
#include <vector>
#include <mutex>
#include "maidsafe/common/config.h"

namespace maidsafe {

namespace encrypt {


Cache::Cache(uint32_t max_size)
    : cache_(), max_size_(max_size), start_(0) {}


void Cache::Put(std::vector<char> data, uint64_t position) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (position < start_ || (position > (start_ + cache_.size()) < position)) {
    cache_.clear();
    start_ = position;
    cache_ = data;
  } else {
    std::copy_n(std::begin(data), data.size(), std::back_inserter(cache_));
  }
  while (cache_.size() > max_size_) {
    cache_.erase(std::begin(cache_), std::begin(cache_) + kMaxChunkSize);
    start_ -= kMaxChunkSize;
  }
}

bool Cache::Get(std::vector<char>& data, uint32_t length, uint64_t file_position) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (file_position > start_ + cache_.size() || file_position < start_)
    return false;

  auto offset(file_position - start_);
  if (offset + length > cache_.size())
    return false;

  std::copy_n(std::begin(cache_) + offset, length, std::back_inserter(data));
  return true;
}


}  // namespace encrypt

}  // namespace maidsafe

