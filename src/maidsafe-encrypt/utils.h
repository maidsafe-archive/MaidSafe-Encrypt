/*******************************************************************************
 *  Copyright 2008 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  utils.h
 * @brief Helper functions for self-encryption engine.
 * @date  2008-09-09
 */

#ifndef MAIDSAFE_ENCRYPT_UTILS_H_
#define MAIDSAFE_ENCRYPT_UTILS_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 2
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace fs = boost::filesystem3;

namespace maidsafe {

namespace encrypt {

class DataIOHandler;

namespace utils {

/// Generates encrypted chunks from single source input data.
int EncryptContent(std::shared_ptr<DataIOHandler> input_handler,
                   const fs::path &output_dir,
                   bool try_compression,
                   DataMap *data_map);

/// Assembles output data from encrypted chunks.
int DecryptContent(const DataMap &data_map,
                   const fs::path &input_dir,
                   std::shared_ptr<DataIOHandler> output_handler);

/// Checks file extension against a list of known uncompressible file formats.
bool IsCompressedFile(const fs::path &file_path);

/// Estimates whether compression could result in space savings.
bool CheckCompressibility(std::shared_ptr<DataIOHandler> input_handler);

/// Determines the sizes of the chunks the input data will be split into.
bool CalculateChunkSizes(std::uint64_t data_size,
                         std::vector<std::uint32_t> *chunk_sizes);

/// Deterministically expands an input string to the required size.
bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data);

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
