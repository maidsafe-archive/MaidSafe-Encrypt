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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"

#include "maidsafe/encrypt/byte_array.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/data_map_pb.h"

namespace maidsafe {

namespace encrypt {

int SerialiseDataMap(const DataMap& data_map, std::string& serialised_data_map) {
  if (data_map.content.empty() && data_map.chunks.empty()) {
    LOG(kError) << "Datamap seems empty.";
    return kSerialisationError;
  }

  protobuf::DataMap proto_data_map;
  if (!data_map.content.empty()) {
    LOG(kVerbose) << "Added content";
    proto_data_map.set_content(data_map.content);
  }

  for (auto& chunk_detail : data_map.chunks) {
    protobuf::ChunkDetails* chunk_details = proto_data_map.add_chunk_details();
    chunk_details->set_hash(chunk_detail.hash);
    chunk_details->set_pre_hash(std::string(reinterpret_cast<char const*>(chunk_detail.pre_hash),
                                           crypto::SHA512::DIGESTSIZE));
    chunk_details->set_size(chunk_detail.size);
    chunk_details->set_pre_hash_state(chunk_detail.pre_hash_state);
  }

  if (!proto_data_map.SerializeToString(&serialised_data_map)) {
    LOG(kError) << "Error serialising.";
    return kSerialisationError;
  }

  return kSuccess;
}

bool ExtractChunkDetails(const protobuf::DataMap& proto_data_map, DataMap& data_map) {
  ChunkDetails temp;
  for (int n(0); n < proto_data_map.chunk_details_size(); ++n) {
    temp.hash = proto_data_map.chunk_details(n).hash();
    std::string pre_hash(proto_data_map.chunk_details(n).pre_hash());
    if (pre_hash.size() == size_t(crypto::SHA512::DIGESTSIZE)) {
      for (int ch(0); ch < crypto::SHA512::DIGESTSIZE; ++ch)
        temp.pre_hash[ch] = pre_hash.at(ch);
    } else {
      LOG(kError) << "Clearing details vector. Incorrect pre hash size in PB: " << pre_hash.size();
      data_map.chunks.clear();
      return false;
    }
    temp.size = proto_data_map.chunk_details(n).size();
    temp.pre_hash_state =
        static_cast<ChunkDetails::PreHashState>(proto_data_map.chunk_details(n).pre_hash_state());
    data_map.chunks.push_back(temp);
  }

  return true;
}

int ParseDataMap(const std::string& serialised_data_map, DataMap& data_map) {
  protobuf::DataMap proto_data_map;
  if (!proto_data_map.ParseFromString(serialised_data_map)) {
    LOG(kError) << "Error parsing.";
    return kDeserialisationError;
  }

  if (proto_data_map.has_content() && proto_data_map.chunk_details_size() != 0) {
    LOG(kWarning) << "Data map contains both chunks and content";
    data_map.content = proto_data_map.content();
    if (!ExtractChunkDetails(proto_data_map, data_map))
      return kDeserialisationError;
  } else if (proto_data_map.has_content()) {
    data_map.content = proto_data_map.content();
  } else if (proto_data_map.chunk_details_size() != 0) {
    if (!ExtractChunkDetails(proto_data_map, data_map))
      return kDeserialisationError;
  } else {
    LOG(kError) << "No chunks or content - serialised_data_map.size(): "
                << serialised_data_map.size();
    return kDeserialisationError;
  }

  return kSuccess;
}

}  // namespace encrypt

}  // namespace maidsafe
