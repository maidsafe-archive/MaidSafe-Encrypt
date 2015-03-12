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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/data_map_encryptor.h"
#include "maidsafe/encrypt/self_encryptor.h"

namespace maidsafe {

namespace encrypt {

ChunkDetails::ChunkDetails(ChunkDetails&& other) MAIDSAFE_NOEXCEPT
    : hash(std::move(other.hash)),
      pre_hash(std::move(other.pre_hash)),
      storage_state(std::move(other.storage_state)),
      size(std::move(other.size)) {}

ChunkDetails& ChunkDetails::operator=(ChunkDetails&& other) MAIDSAFE_NOEXCEPT {
  hash = std::move(other.hash);
  pre_hash = std::move(other.pre_hash);
  storage_state = std::move(other.storage_state);
  size = std::move(other.size);
  return *this;
}

DataMap::DataMap() : self_encryption_version(kSelfEncryptionVersion), chunks(), content() {}

DataMap::DataMap(DataMap&& other) MAIDSAFE_NOEXCEPT
    : self_encryption_version(std::move(other.self_encryption_version)),
      chunks(std::move(other.chunks)),
      content(std::move(other.content)) {}

DataMap& DataMap::operator=(DataMap&& other) MAIDSAFE_NOEXCEPT {
  self_encryption_version = std::move(other.self_encryption_version);
  chunks = std::move(other.chunks);
  content = std::move(other.content);
  return *this;
}

uint64_t DataMap::size() const {
  return chunks.empty() ? content.size() :
                          static_cast<uint64_t>(chunks[0].size) * (chunks.size() - 2) +
                              (++chunks.rbegin())->size + chunks.rbegin()->size;
}

bool DataMap::empty() const { return chunks.empty() && content.empty(); }

bool operator==(const DataMap& lhs, const DataMap& rhs) {
  if (lhs.self_encryption_version != rhs.self_encryption_version || lhs.content != rhs.content ||
      lhs.chunks.size() != rhs.chunks.size()) {
    return false;
  }

  for (uint32_t i = 0; i < lhs.chunks.size(); ++i) {
    if (lhs.chunks[i].hash != rhs.chunks[i].hash)
      return false;
  }

  return true;
}

bool operator!=(const DataMap& lhs, const DataMap& rhs) { return !(lhs == rhs); }

}  // namespace encrypt

}  // namespace maidsafe
