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

#ifndef MAIDSAFE_ENCRYPT_DATA_MAP_H_
#define MAIDSAFE_ENCRYPT_DATA_MAP_H_

#include <cstdint>
#include <string>
#include <vector>

#include "maidsafe/common/config.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/serialisation/serialisation.h"

namespace maidsafe {

namespace encrypt {

using ByteVector = std::vector<byte>;

enum class EncryptionAlgorithm : uint32_t {
  kSelfEncryptionVersion0 = 0,
  kDataMapEncryptionVersion0
};

struct ChunkDetails {
  enum StorageState { kStored, kPending, kUnstored };
  ChunkDetails() : hash(), pre_hash(), storage_state(kUnstored), size(0) {}
  ChunkDetails(const ChunkDetails&) = default;
  ChunkDetails(ChunkDetails&&) MAIDSAFE_NOEXCEPT;
  ChunkDetails& operator=(const ChunkDetails&) = default;
  ChunkDetails& operator=(ChunkDetails&& other) MAIDSAFE_NOEXCEPT;
  ~ChunkDetails() = default;

  template <typename Archive>
  Archive& serialize(Archive& archive) {
    return archive(hash, pre_hash, storage_state, size);
  }

  ByteVector hash;      // SHA512 of processed chunk
  ByteVector pre_hash;  // SHA512 of unprocessed src data
  // pre hashes of chunks n-1 and n-2, only valid if chunk n-1 or n-2 has
  // modified content
  StorageState storage_state;
  uint32_t size;  // Size of unprocessed source data in bytes
};

struct DataMap {
  DataMap();
  DataMap(const DataMap&) = default;
  DataMap(DataMap&& other) MAIDSAFE_NOEXCEPT;
  DataMap& operator=(const DataMap&) = default;
  DataMap& operator=(DataMap&& other) MAIDSAFE_NOEXCEPT;
  ~DataMap() = default;
  uint64_t size() const;
  bool empty() const;

  template <typename Archive>
  Archive& serialize(Archive& archive) {
    return archive(self_encryption_version, chunks, content);
  }

  EncryptionAlgorithm self_encryption_version;
  std::vector<ChunkDetails> chunks;
  ByteVector content;  // Whole data item, if small enough
};

bool operator==(const DataMap& lhs, const DataMap& rhs);
bool operator!=(const DataMap& lhs, const DataMap& rhs);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
