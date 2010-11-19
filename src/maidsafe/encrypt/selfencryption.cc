/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Self-encryption and self-decryption engine
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/encrypt/selfencryption.h"

#include <set>

#include "maidsafe/encrypt/dataiohandler.h"
#include "maidsafe/encrypt/datamap.pb.h"
#include "maidsafe/encrypt/selfencryptionconfig.h"
#include "maidsafe/encrypt/selfencryptionutils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

int SelfEncryptFile(const fs::path &input_file,
                    const fs::path &output_dir,
                    DataMap *data_map/*,
                    std::set<std::string> *done_chunks*/) {
  std::map<std::string, fs::path> to_chunk_store;
  std::tr1::shared_ptr<DataIOHandler> input_handler(
      new FileIOHandler(input_file, true));
  return utils::EncryptContent(input_handler, output_dir, data_map,
                               &to_chunk_store);
}

int SelfEncryptString(const std::string &input_string,
                      const fs::path &output_dir,
                      DataMap *data_map/*,
                      std::set<std::string> *done_chunks*/) {
  std::map<std::string, fs::path> to_chunk_store;
  std::tr1::shared_ptr<DataIOHandler> input_handler(
      new StringIOHandler(std::tr1::shared_ptr<std::string>(
          new std::string(input_string)), true));
  return utils::EncryptContent(input_handler, output_dir, data_map,
                               &to_chunk_store);
}

int SelfDecryptToFile(const DataMap &data_map,
                      const std::vector<fs::path> &chunk_paths,
                      const boost::uint64_t &offset,
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
  std::tr1::shared_ptr<DataIOHandler> output_handler(
      new FileIOHandler(output_file, false));
  return utils::DecryptContent(data_map, chunk_paths, offset, output_handler);
}

int SelfDecryptToString(const DataMap &data_map,
                        const std::vector<fs::path> &chunk_paths,
                        const boost::uint64_t &offset,
                        std::tr1::shared_ptr<std::string> output_string) {
  if (output_string)
    output_string->clear();
  else
    output_string.reset(new std::string);
  std::tr1::shared_ptr<DataIOHandler> output_handler(
      new StringIOHandler(output_string, false));
  return utils::DecryptContent(data_map, chunk_paths, offset, output_handler);
}

int EncryptDataMap(const DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map) {
  return utils::EncryptDataMap(data_map, this_directory_key,
                               parent_directory_key, encrypted_data_map);
}

int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   DataMap *data_map) {
  return utils::DecryptDataMap(encrypted_data_map, this_directory_key,
                               parent_directory_key, data_map);
}

}  // namespace encrypt

}  // namespace maidsafe
