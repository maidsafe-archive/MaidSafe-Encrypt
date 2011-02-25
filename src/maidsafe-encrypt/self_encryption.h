/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  self_encryption.h
 * @brief Provides self-encryption/self-decryption functionality.
 * @date  2008-09-09
 */

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_

#include <iostream>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 4
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

struct DataMap;
struct SelfEncryptionParams;

/// Generates secure chunks from a stream.
int SelfEncrypt(std::istream *input_stream,
                const fs::path &output_dir,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                DataMap *data_map);

/// Generates secure chunks from a string.
int SelfEncrypt(const std::string &input_string,
                const fs::path &output_dir,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                DataMap *data_map);

/// Generates secure chunks from a file.
int SelfEncrypt(const fs::path &input_file,
                const fs::path &output_dir,
                const SelfEncryptionParams &self_encryption_params,
                DataMap *data_map);

/// Restores data from secure chunks to a stream.
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                std::ostream *output_stream);

/// Restores data from secure chunks to a string.
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                std::string *output_string);

/// Restores data from secure chunks to a file.
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                bool overwrite,
                const fs::path &output_file);

/// Checks for existance of each chunk file referred to by the DataMap.
bool ChunksExist(const DataMap &data_map,
                 const fs::path &input_dir,
                 std::vector<std::string> *missing_chunks);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_
