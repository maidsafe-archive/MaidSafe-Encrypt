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
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem3;

namespace maidsafe {

namespace encrypt {

/**
 * Splits input file into chunks, compresses them if possible, obfuscates and
 * then encrypts them.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_file The file to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param data_map DataMap to be populated with chunk information.
 * @return Result of the operation.
 */
int SelfEncryptFile(const fs::path &input_file,
                    const fs::path &output_dir,
                    DataMap *data_map) {
  std::shared_ptr<DataIOHandler> input_handler(
      new FileIOHandler(input_file, true));
  return utils::EncryptContent(input_handler, output_dir,
                               utils::IsCompressedFile(input_file), data_map);
}

/**
 * Splits input string into chunks, compresses them if possible, obfuscates and
 * then encrypts them.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_string The string to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param data_map DataMap to be populated with chunk information.
 * @return Result of the operation.
 */
int SelfEncryptString(const std::string &input_string,
                      const fs::path &output_dir,
                      DataMap *data_map) {
  std::shared_ptr<DataIOHandler> input_handler(
      new StringIOHandler(const_cast<std::string*>(&input_string), true));
  return utils::EncryptContent(input_handler, output_dir, true, data_map);
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param overwrite Whether to overwrite an already existing output file.
 * @param output_file Path to the resulting file.
 * @return Result of the operation.
 */
int SelfDecryptToFile(const DataMap &data_map,
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
    return kDecryptError;
  }
  std::shared_ptr<DataIOHandler> output_handler(
      new FileIOHandler(output_file, false));
  return utils::DecryptContent(data_map, input_dir, output_handler);
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param output_string Pointer to resulting string.
 * @return Result of the operation.
 */
int SelfDecryptToString(const DataMap &data_map,
                        const fs::path &input_dir,
                        std::string *output_string) {
  if (!output_string)
    return kDecryptError;
  output_string->clear();
  std::shared_ptr<DataIOHandler> output_handler(
      new StringIOHandler(output_string, false));
  return utils::DecryptContent(data_map, input_dir, output_handler);
}

}  // namespace encrypt

}  // namespace maidsafe
