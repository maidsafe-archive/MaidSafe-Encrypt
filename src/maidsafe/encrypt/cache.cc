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


Cache::Cache(uint32_t max_size) : cache_(), max_size_(max_size), cache_start_position_(0) {}


void Cache::Put(std::vector<byte> data, uint64_t position) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (data.empty() || (max_size_ == 0))
    return;

  if (position < cache_start_position_ || (position > (cache_start_position_ + cache_.size()))) {
    cache_.clear();
    cache_start_position_ = position;
    cache_.reserve(cache_.size() + data.size());
    cache_ = std::move(data);
  } else {
    // assume position > start
    auto offset(position - cache_start_position_);
    auto data_size = data.size();
    cache_.reserve(cache_.size() + data_size);
    // Insert data to offset
    cache_.insert(std::begin(cache_) + offset, std::begin(data), std::end(data));
    // remove invalidated data
    if (cache_.size() > data.size())
      cache_.erase(std::begin(cache_) + offset + data_size,
                   std::begin(cache_) + std::min(offset + (2 * data_size), cache_.size()));
  }
  // grown too large, split in two (from the beginning)
  if (cache_.size() > max_size_) {
    cache_.erase(std::begin(cache_), std::begin(cache_) + (max_size_ / 2));
    cache_start_position_ += (max_size_ / 2);
  }
}

bool Cache::Get(std::vector<byte>& data, uint32_t length, uint64_t file_position) const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (cache_.empty())
    return false;

  if (file_position > cache_start_position_ + cache_.size() ||
      file_position < cache_start_position_)
    return false;

  auto offset(file_position - cache_start_position_);
  if (offset + length > cache_.size())
    return false;

  data.insert(std::begin(data), std::begin(cache_) + offset, std::begin(cache_) + offset + length);
  return true;
}


}  // namespace encrypt

}  // namespace maidsafe
