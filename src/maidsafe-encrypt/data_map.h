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

#include "boost/serialization/string.hpp"
#include "boost/serialization/vector.hpp"
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 4
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace maidsafe {

namespace encrypt {

/// Available types of compression
enum CompressionType {
  kNoCompression,   ///< Leave data uncompressed
  kGzipCompression  ///< Use GNU zip compression
};

/// Available types of self-encryption
enum SelfEncryptionType {
  kObfuscate3AES256  ///< Obfuscate over 3 chunks, encrypt with AES256
};

/// Holds information about a chunk
struct ChunkDetails {
  ChunkDetails()
    : hash(), size(0), pre_hash(), pre_size(0), content() {}
  std::string hash;        ///< Hash of processed chunk
  std::uint32_t size;      ///< Size of processed chunk
  std::string pre_hash;    ///< Hash of unprocessed source data
  std::uint32_t pre_size;  ///< Size of unprocessed source data
  std::string content;     ///< Chunk contents, if small enough
};

/// Holds information about the building blocks of a data item
struct DataMap {
  DataMap()
    : compression_type(kNoCompression), self_encryption_type(kObfuscate3AES256),
      chunks(), size(0), content() {}
  CompressionType compression_type;  ///< Type of compression used for contents
  SelfEncryptionType self_encryption_type;  ///< Type of SE used for chunks
  std::vector<ChunkDetails> chunks;  ///< Information about the chunks
  std::uint64_t size;      ///< Size of data item
  std::string content;     ///< Data item contents, if small enough
};

}  // namespace encrypt

}  // namespace maidsafe

namespace boost {

namespace serialization {

template<class Archive>
void serialize(Archive &archive,  // NOLINT
               maidsafe::encrypt::ChunkDetails &chunk_details,
               const unsigned int /* version */) {
  archive & chunk_details.hash;
  archive & chunk_details.size;
  archive & chunk_details.pre_hash;
  archive & chunk_details.pre_size;
  archive & chunk_details.content;
}

template<class Archive>
void serialize(Archive &archive,  // NOLINT
               maidsafe::encrypt::DataMap &data_map,
               const unsigned int /* version */) {
  archive & data_map.compression_type;
  archive & data_map.self_encryption_type;
  archive & data_map.chunks;
  archive & data_map.size;
  archive & data_map.content;
}

}  // namespace serialization

}  // namespace boost

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
