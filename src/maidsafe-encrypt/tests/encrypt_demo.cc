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
 * @file  encrypt_demo.cc
 * @brief Main program for Encrypt demo app.
 * @date  2011-03-05
 */

#include <stdio.h>
#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem;
namespace mse = maidsafe::encrypt;

namespace maidsafe {

namespace encrypt {

namespace demo {

enum ReturnCodes {
  kSuccess = 0,
  kNoArgumentsError,
  kCommandError,
  kWrongArgumentsError,
  kGenerateError,
  kEncryptError
};

int Generate(const int &chunk_size,
             const std::string &pattern,
             const fs::path &file_name) {
  if (chunk_size < 1) {
    printf("Error: Chunk size must be bigger than zero.\n");
    return kGenerateError;
  }

  std::string content;
  for (size_t i = 0; i < pattern.size(); ++i)
    if (pattern[i] == '#')
      content.append(RandomString(chunk_size));
    else
      content.append(chunk_size, pattern[i]);

  if (!utils::WriteFile(file_name, content)) {
    printf("Error: Could not write contents to file '%s'.\n",
           file_name.c_str());
    return kGenerateError;
  }

  return kSuccess;
}

int Encrypt(const fs::path &input_path, const fs::path &output_path,
            const SelfEncryptionParams &self_encryption_params) {
  if (!fs::exists(input_path) || fs::is_directory(input_path)) {
    printf("Error: Encryption input file not found.\n");
    return kEncryptError;
  }

  if (!fs::exists(output_path) || !fs::is_directory(output_path)) {
    printf("Error: Encryption output directory not found.\n");
    return kEncryptError;
  }

  DataMap data_map;
  if (SelfEncrypt(input_path, output_path, self_encryption_params, &data_map) !=
      kSuccess) {
    printf("Error: Self-encryption failed.\n");
    return kEncryptError;
  }

  return kSuccess;
}

}  // namespace demo

}  // namespace encrypt

}  // namespace maidsafe

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("Demo application for MaidSafe-Encrypt\n\n"
           "Usage: %s <command> [<argument>...]\n\n"
           "The following commands are available:\n"
           "  generate <chunk-size> <pattern> <file-name>\n"
           "    Generates a file by writing chunks of the given size according "
                "to a\n    pattern, in which each character represents the "
                "chunk contents. The given\n    character gets repeated, with "
                "the exception of '#', which results in a\n    random chunk. "
                "Example: \"gen 128 aabaa#aab file.dat\"\n"
           "  encrypt <input-file> <output-dir>\n"
           "    Applies self-encryption to the given file, with chunks being "
                "stored in the\n    given output directory.\n",
           argv[0]);
    return mse::demo::kNoArgumentsError;
  }

  std::string command(boost::to_lower_copy(std::string(argv[1])));
  if (command == "generate") {
    if (argc == 5) {
      int chunk_size(0);
      try {
        chunk_size = boost::lexical_cast<int>(std::string(argv[2]));
      }
      catch(...) {}
      return mse::demo::Generate(chunk_size, argv[3], argv[4]);
    }
  } else if (command == "encrypt") {
    if (argc == 4) {
      mse::SelfEncryptionParams sep;
      return mse::demo::Encrypt(argv[2], argv[3], sep);
    }
  } else {
    printf("Error: Unrecognised command '%s'.\n", command.c_str());
    return mse::demo::kCommandError;
  }

  printf("Error: Wrong number of arguments supplied to command '%s' (%d).\n",
         command.c_str(), argc - 2);
  return mse::demo::kWrongArgumentsError;
}
