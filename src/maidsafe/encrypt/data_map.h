
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
#include "boost/serialization/string.hpp"
#include "boost/serialization/vector.hpp"

#include "maidsafe/encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION != 906
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-encrypt library.
#endif

namespace maidsafe {
namespace encrypt {

struct ChunkDetails {
  ChunkDetails() : hash(), pre_hash(), size(0) {}
  byte hash[crypto::SHA512::DIGESTSIZE];  // SHA512 of processed chunk
  byte pre_hash[crypto::SHA512::DIGESTSIZE];  // SHA512 of unprocessed src data
  uint32_t size;  // Size of unprocessed source data in bytes
};

struct DataMap {
  DataMap() : chunks(), content() {}
  std::vector<ChunkDetails> chunks;
  std::string content;  // Whole data item, if small enough
};

typedef std::shared_ptr<DataMap> DataMapPtr;

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


namespace boost {
namespace serialization {

template<class Archive>
void serialize(Archive &archive,  // NOLINT
               maidsafe::encrypt::ChunkDetails &chunk_details,
               const unsigned int /* version */) {
  archive &chunk_details.hash;
  archive &chunk_details.pre_hash;
  archive &chunk_details.size;
}

template<class Archive>
void serialize(Archive &archive,  // NOLINT
               maidsafe::encrypt::DataMap &data_map,
               const unsigned int /* version */) {
  archive &data_map.chunks;
  archive &data_map.content;
}

}  // namespace serialization
}  // namespace boost

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
