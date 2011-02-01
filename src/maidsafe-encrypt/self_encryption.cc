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
 * @file  self_encryption.cc
 * @brief Provides self-encryption/self-decryption functionality.
 * @date  2008-09-09
 */

#include "maidsafe-encrypt/self_encryption.h"

#include <set>

#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_io_handler.h"
#include "maidsafe-encrypt/data_map.pb.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

/**
 * Splits input file into chunks/chunklets, compresses them if possible,
 * obfuscates and then encrypts them.
 *
 * Derived chunks will be created in output_dir. If data_map already has entry
 * for file hash, this will be used.
 *
 * @param input_file The file to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param data_map DataMap to be populated with chunk information.
 * @return Result of the operation.
 */
int SelfEncryptFile(const fs::path &input_file,
                    const fs::path &output_dir,
                    protobuf::DataMap *data_map/*,
                    std::set<std::string> *done_chunks*/) {
  std::map<std::string, fs::path> to_chunk_store;
  std::shared_ptr<DataIOHandler> input_handler(
      new FileIOHandler(input_file, true));
  return utils::EncryptContent(input_handler, output_dir, data_map,
                               &to_chunk_store);
}

/**
 * Splits input string into chunks/chunklets, compresses them if possible,
 * obfuscates and then encrypts them.
 *
 * Derived chunks will be created in output_dir. If data_map already has entry
 * for file hash, this will be used.
 *
 * @param input_string The string to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param data_map DataMap to be populated with chunk information.
 * @return Result of the operation.
 */
int SelfEncryptString(const std::string &input_string,
                      const fs::path &output_dir,
                      protobuf::DataMap *data_map/*,
                      std::set<std::string> *done_chunks*/) {
  std::map<std::string, fs::path> to_chunk_store;
  std::shared_ptr<DataIOHandler> input_handler(
      new StringIOHandler(std::shared_ptr<std::string>(
          new std::string(input_string)), true));
  return utils::EncryptContent(input_handler, output_dir, data_map,
                               &to_chunk_store);
}

/**
 * Decrypts chunks to output_file starting at chunklet spanning offset point.
 * All neccessary chunks should be available and listed in chunk_paths
 * (preferrably in same order as listed in data_map) and named as hex-encoded
 * encrypted_chunk_name.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_paths Vector of paths to all the input chunks.
 * @param offset Point in source data to start reconstruction at.
 * @param overwrite Whether to overwrite an already existing output file.
 * @param output_file Path to the resulting file.
 * @return Result of the operation.
 */
int SelfDecryptToFile(const protobuf::DataMap &data_map,
                      const std::vector<fs::path> &chunk_paths,
                      const std::uint64_t &offset,
                      bool overwrite,
                      const fs::path &output_file) {
  try {
    if (fs::exists(output_file)) {
      if (overwrite)
        fs::remove(output_file);
      else
        return kFileAlreadyExists;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SelfDecryptToFile: %s\n", e.what());
#endif
    return kDecryptError;
  }
  std::shared_ptr<DataIOHandler> output_handler(
      new FileIOHandler(output_file, false));
  return utils::DecryptContent(data_map, chunk_paths, offset, output_handler);
}

/**
 * Decrypts chunks to output_string starting at chunklet spanning offset point.
 * All neccessary chunks should be available and listed in chunk_paths
 * (preferrably in same order as listed in data_map) and named as hex-encoded
 * encrypted_chunk_name.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_paths Vector of paths to all the input chunks.
 * @param offset Point in source data to start reconstruction at.
 * @param output_string Pointer to result string.
 * @return Result of the operation.
 */
int SelfDecryptToString(const protobuf::DataMap &data_map,
                        const std::vector<fs::path> &chunk_paths,
                        const std::uint64_t &offset,
                        std::shared_ptr<std::string> output_string) {
  if (output_string)
    output_string->clear();
  else
    output_string.reset(new std::string);
  std::shared_ptr<DataIOHandler> output_handler(
      new StringIOHandler(output_string, false));
  return utils::DecryptContent(data_map, chunk_paths, offset, output_handler);
}

int EncryptDataMap(const protobuf::DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map) {
  return utils::EncryptDataMap(data_map, this_directory_key,
                               parent_directory_key, encrypted_data_map);
}

int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   protobuf::DataMap *data_map) {
  return utils::DecryptDataMap(encrypted_data_map, this_directory_key,
                               parent_directory_key, data_map);
}

}  // namespace encrypt

}  // namespace maidsafe
