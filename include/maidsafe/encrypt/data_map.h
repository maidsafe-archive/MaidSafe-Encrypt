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

#ifndef MAIDSAFE_ENCRYPT_DATA_MAP_H_
#define MAIDSAFE_ENCRYPT_DATA_MAP_H_

#include <cstdint>
#include <string>
#include <vector>

#include "maidsafe/common/crypto.h"
#include "boost/shared_array.hpp"


namespace maidsafe {

namespace encrypt {

struct ChunkDetails {
  enum PreHashState { kEmpty, kOutdated, kOk };
  enum StorageState { kStored, kPending, kUnstored };
  ChunkDetails() : hash(),
                   pre_hash(),
                   old_n1_pre_hash(),
                   old_n2_pre_hash(),
                   pre_hash_state(kEmpty),
                   storage_state(kUnstored),
                   size(0) {}
  std::string hash;  // SHA512 of processed chunk
  byte pre_hash[crypto::SHA512::DIGESTSIZE];  // SHA512 of unprocessed src data
  // pre hashes of chunks n-1 and n-2, only valid if chunk n-1 or n-2 has
  // modified content
  boost::shared_array<byte> old_n1_pre_hash, old_n2_pre_hash;
  // If the pre_hash hasn't been calculated, or if data has been written to the
  // chunk since the pre_hash was last calculated, pre_hash_ok should be false.
  PreHashState pre_hash_state;
  StorageState storage_state;
  uint32_t size;  // Size of unprocessed source data in bytes
};

struct DataMap {
  DataMap() : chunks(), content() {}

  bool operator==(const DataMap &other) const {
    if (!this)
      return false;

    if (content != other.content || chunks.size() != other.chunks.size())
      return false;

    for (uint32_t i = 0; i < chunks.size(); ++i)
      if (chunks[i].hash != other.chunks[i].hash)
        return false;

    return true;
  }

  bool operator!=(const DataMap &other) const { return !(*this == other); }

  std::vector<ChunkDetails> chunks;
  std::string content;  // Whole data item, if small enough
};

typedef std::shared_ptr<DataMap> DataMapPtr;

void SerialiseDataMap(const DataMap& data_map, std::string& serialised_data_map);
void ParseDataMap(const std::string& serialised_data_map, DataMap& data_map);

/*
// Hold datamaps in a version container
struct VersionedDataMap {
  VersionedDataMap()
    : data_map(), user_name(), time_stamp() {}
  DataMap data_map;
  std::string user_name;
  boost::posix_time::time_duration time_stamp;
};

std::tuple<uint8_t, fs::path, VersionedDataMap> VersionedDirMap; // for dirs
*/

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
