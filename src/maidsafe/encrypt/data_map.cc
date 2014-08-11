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

#include "maidsafe/encrypt/byte_array.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/data_map_encryptor.h"
#include "maidsafe/encrypt/data_map.pb.h"
#include "maidsafe/encrypt/self_encryptor.h"

namespace maidsafe {

namespace encrypt {

ChunkDetails::ChunkDetails(ChunkDetails&& other) MAIDSAFE_NOEXCEPT
    : hash(std::move(other.hash)),
      pre_hash(std::move(other.pre_hash)),
      storage_state(std::move(other.storage_state)),
      size(std::move(other.size)) {}

DataMap::DataMap() : self_encryption_version(kSelfEncryptionVersion), chunks(), content() {}

DataMap::DataMap(DataMap&& other) MAIDSAFE_NOEXCEPT
    : self_encryption_version(std::move(other.self_encryption_version)),
      chunks(std::move(other.chunks)),
      content(std::move(other.content)) {}

uint64_t DataMap::size() const {
  return chunks.empty()
             ? content.size()
             : static_cast<uint64_t>(chunks[0].size) * (chunks.size() - 1) + chunks.rbegin()->size;
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

void SerialiseDataMap(const DataMap& data_map, std::string& serialised_data_map) {
  protobuf::DataMap proto_data_map;
  proto_data_map.set_self_encryption_version(
      static_cast<uint32_t>(data_map.self_encryption_version));
  if (!data_map.content.empty()) {
    proto_data_map.set_content(
        std::string(std::begin(data_map.content), std::end(data_map.content)));
  } else {
    for (auto& chunk_detail : data_map.chunks) {
      protobuf::ChunkDetails* chunk_details = proto_data_map.add_chunk_details();
      chunk_details->set_hash(
          std::string(std::begin(chunk_detail.hash), std::end(chunk_detail.hash)));
      chunk_details->set_pre_hash(
          std::string(std::begin(chunk_detail.pre_hash), std::end(chunk_detail.pre_hash)));
      chunk_details->set_size(chunk_detail.size);
      chunk_details->set_storage_state(chunk_detail.storage_state);
    }
  }
  if (!proto_data_map.SerializeToString(&serialised_data_map))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::serialisation_error));
}

void ExtractChunkDetails(const protobuf::DataMap& proto_data_map, DataMap& data_map) {
  ChunkDetails temp;
  for (int n(0); n < proto_data_map.chunk_details_size(); ++n) {
    temp.hash = ByteVector(std::begin(proto_data_map.chunk_details(n).hash()),
                           std::end(proto_data_map.chunk_details(n).hash()));
    temp.pre_hash = ByteVector(std::begin(proto_data_map.chunk_details(n).pre_hash()),
                               std::end(proto_data_map.chunk_details(n).pre_hash()));

    temp.size = proto_data_map.chunk_details(n).size();
    temp.storage_state =
        static_cast<ChunkDetails::StorageState>(proto_data_map.chunk_details(n).storage_state());
    data_map.chunks.push_back(temp);
  }
}

void ParseDataMap(const std::string& serialised_data_map, DataMap& data_map) {
  protobuf::DataMap proto_data_map;
  if (!proto_data_map.ParseFromString(serialised_data_map))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));

  data_map.self_encryption_version =
      static_cast<EncryptionAlgorithm>(proto_data_map.self_encryption_version());
  if (proto_data_map.has_content() && proto_data_map.chunk_details_size() != 0) {
    data_map.content =
        ByteVector(std::begin(proto_data_map.content()), std::end(proto_data_map.content()));
    ExtractChunkDetails(proto_data_map, data_map);
  } else if (proto_data_map.has_content()) {
    data_map.content =
        ByteVector(std::begin(proto_data_map.content()), std::end(proto_data_map.content()));
  } else if (proto_data_map.chunk_details_size() != 0) {
    ExtractChunkDetails(proto_data_map, data_map);
  }
}

}  // namespace encrypt

}  // namespace maidsafe
