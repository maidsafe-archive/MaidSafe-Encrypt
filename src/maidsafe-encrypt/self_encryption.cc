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

#include <iostream>
#include <set>
#include <sstream>

#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_io_handler.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem3;

namespace maidsafe {

namespace encrypt {

/**
 * Splits data from input stream into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_stream The stream providing data to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param try_compression Whether to attempt compression of the data.
 * @param data_map DataMap to be populated with chunk metadata.
 * @return Result of the operation.
 */
int SelfEncrypt(std::istream *input_stream,
                const fs::path &output_dir,
                bool try_compression,
                DataMap *data_map) {
  return utils::EncryptContent(input_stream, output_dir, try_compression,
                               data_map);
}

/**
 * Splits data from input string into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_string The string providing data to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param try_compression Whether to attempt compression of the data.
 * @param data_map DataMap to be populated with chunk metadata.
 * @return Result of the operation.
 */
int SelfEncrypt(const std::string &input_string,
                const fs::path &output_dir,
                bool try_compression,
                DataMap *data_map) {
  std::istringstream input_stream(input_string);
  return utils::EncryptContent(&input_stream, output_dir, try_compression,
                               data_map);
}

/**
 * Splits data from input file into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Based on the file extension, a decision is made whether an attempt to
 * compress the data should be undertaken. Use SelfEncrypt for streams if you
 * want to override this behaviour.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_file The file providing data to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param data_map DataMap to be populated with chunk metadata.
 * @return Result of the operation.
 */
int SelfEncrypt(const fs::path &input_file,
                const fs::path &output_dir,
                DataMap *data_map) {
  fs::ifstream input_stream(input_file, std::ios::in | std::ios::binary);
  int result(utils::EncryptContent(&input_stream, output_dir,
                                   utils::IsCompressedFile(input_file),
                                   data_map));
  input_stream.close();
  return result;
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param output_stream Pointer to stream receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                std::ostream *output_stream) {
  return utils::DecryptContent(data_map, input_dir, output_stream);
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param output_string Pointer to string receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                std::string *output_string) {
  if (!output_string)
    return kDecryptError;
  std::ostringstream output_stream;
  int result(utils::DecryptContent(data_map, input_dir, &output_stream));
  *output_string = output_stream.str();
  return result;
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param overwrite Whether to overwrite an already existing output file.
 * @param output_file Path to file receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
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
    return kFilesystemError;
  }
  fs::ofstream output_stream(output_file, std::ios::out | std::ios::trunc |
                                          std::ios::binary);
  int result(utils::DecryptContent(data_map, input_dir, &output_stream));
  output_stream.close();
  return result;
}

}  // namespace encrypt

}  // namespace maidsafe
