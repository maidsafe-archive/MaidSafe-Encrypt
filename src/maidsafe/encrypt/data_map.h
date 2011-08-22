/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  data_map.h
 * @brief Provides data structures for the DataMap.
 * @date  2008-09-09
 */

#ifndef MAIDSAFE_ENCRYPT_DATA_MAP_H_
#define MAIDSAFE_ENCRYPT_DATA_MAP_H_

#include <cstdint>
#include <string>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4702)
#endif
#include "cryptopp/cryptlib.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "boost/serialization/string.hpp"
#include "boost/serialization/vector.hpp"
#include "maidsafe/encrypt/version.h"
#include <cryptopp/sha.h>

#if MAIDSAFE_ENCRYPT_VERSION != 905
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-encrypt library.
#endif

namespace maidsafe {

namespace encrypt {

/// Holds information about a chunk
struct ChunkDetails {
  ChunkDetails()
    : hash(), pre_hash(), size(0) {}
  byte hash[CryptoPP::SHA512::DIGESTSIZE];        /// processed chunk
  byte pre_hash[CryptoPP::SHA512::DIGESTSIZE];  /// unprocessed source data
  std::uint32_t size;  ///< Size of unprocessed source data
};

/// Holds information about the building blocks of a data item
struct DataMap {
  DataMap()
    : self_encryption_type(0), chunks(), size(0), content(), content_size(0) {}
  std::uint32_t self_encryption_type;  ///< Type of SE used for chunks
  std::vector<ChunkDetails> chunks;  ///< Information about the chunks
  std::uint64_t size;      ///< Size of data item
  std::string content;     ///< Whole data item or last chunk, if small enough
  std::uint16_t content_size;
};

/*
/// Hold datamaps in a version container
struct VersionedDataMap {
  VersionedDataMap()
    : data_map(), user_name(), time_stamp() {}
  DataMap data_map;
  std::string user_name;
  boost::posix_time::time_duration time_stamp;
};*/
/*
std::tuple<uint8_t, fs::path, VersionedDataMap> VersionedDirMap; // for dirs*/

}  // namespace encrypt

}  // namespace maidsafe

namespace boost {

namespace serialization {

template<class Archive>
void serialize(Archive &archive,  // NOLINT
               maidsafe::encrypt::ChunkDetails &chunk_details,
               const unsigned int /* version */) {
  archive & chunk_details.hash;
  archive & chunk_details.pre_hash;
  archive & chunk_details.size;
}

template<class Archive>
void serialize(Archive &archive,  // NOLINT
               maidsafe::encrypt::DataMap &data_map,
               const unsigned int /* version */) {
  archive & data_map.self_encryption_type;
  archive & data_map.chunks;
  archive & data_map.size;
  archive & data_map.content;
}

}  // namespace serialization

}  // namespace boost

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
