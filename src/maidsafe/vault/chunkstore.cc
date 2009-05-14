/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose
 */

#include "maidsafe/vault/chunkstore.h"

#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_array.hpp>
#include <boost/thread/mutex.hpp>
#include <ctime>

#include "base/utils.h"

namespace maidsafe_vault {

ChunkStore::ChunkStore(const std::string &chunkstore_dir)
    : chunkstore_dir_(chunkstore_dir),
      init_(false),
      crypto_() {
  Init();
}

bool ChunkStore::Init() {
  init_ = false;
  fs::path chunkstore_path_(chunkstore_dir_, fs::native);
//  chunkstore_path_ /= "STORAGE";
  try {
    if (fs::exists(chunkstore_path_)) {
      init_ = true;
    } else {
      init_ = fs::create_directories(chunkstore_path_);
    }
  }
  catch(const std::exception &ex) {
    printf("ChunkStore::Init can not create dir %s\nException: %s\n",
           chunkstore_path_.string().c_str(), ex.what());
  }
  crypto_.set_symm_algorithm("AES_256");
  crypto_.set_hash_algorithm("SHA512");
  return init_;
}

bool ChunkStore::HasChunk(const std::string &key) {
  if (!init_)
    return false;
  fs::path filename(GetPathFromKey(key));
  return fs::exists(filename);
}

bool ChunkStore::StoreChunk(const std::string &key, const std::string &value) {
  if (!init_) {
#ifdef DEBUG
    printf("No init in ChunkStore::StoreChunk.\n");
#endif
    return false;
  }
  fs::path filename(GetPathFromKey(key));
  if (fs::exists(filename)) {
#ifdef DEBUG
    printf("Filename exists in ChunkStore::StoreChunk.\n");
#endif
    return false;
  }
  try {
    uint64_t size(value.size());
    fs::ofstream fstr;
    fstr.open(filename, std::ios_base::binary);
    fstr.write(value.c_str(), size);
    fstr.close();
    return true;
  }
  catch(const std::exception &ex) {
    printf("ChunkStore::StoreChunk exception writing chunk: %s\n", ex.what());
    return false;
  }
}

bool ChunkStore::UpdateChunk(const std::string &key, const std::string &value) {
  if (!init_) {
#ifdef DEBUG
    printf("No init in ChunkStore::UpdateChunk.\n");
#endif
    return false;
  }
  fs::path filename(GetPathFromKey(key));
  if (!DeleteChunk(key)) {
#ifdef DEBUG
    printf("Delete failed in ChunkStore::UpdateChunk.\n");
#endif
    return false;
  }
  try {
    uint64_t size(value.size());
    fs::ofstream fstr;
    fstr.open(filename, std::ios_base::binary);
    fstr.write(value.c_str(), size);
    fstr.close();
    return true;
  }
  catch(const std::exception &ex) {
    printf("ChunkStore::UpdateChunk exception writing chunk: %s\n", ex.what());
    return false;
  }
}

bool ChunkStore::LoadChunk(const std::string &key, std::string *value) {
  if (!init_)
    return false;
  if (!HasChunk(key))
    return false;
  fs::path filename(GetPathFromKey(key));
  uint64_t size(fs::file_size(filename));
  boost::scoped_array<char> temp(new char[size]);
  fs::ifstream fstr;
  fstr.open(filename, std::ios_base::binary);
  fstr.read(temp.get(), size);
  fstr.close();
  std::string result(static_cast<const char*>(temp.get()), size);
  *value = result;
  return true;
}

bool ChunkStore::LoadRandomChunk(std::string *key, std::string *value) {
  {
    if (!init_)
      return false;
    key->clear();
    value->clear();
    std::vector<std::string> files_names;
    fs::directory_iterator end_itr;
    for (fs::directory_iterator itr(chunkstore_dir_); itr != end_itr; ++itr) {
      if (!fs::is_directory(itr->path()))
        files_names.push_back(itr->path().filename());
    }

    if (files_names.size() == 0)
      return false;

    int randindex = static_cast<int>(base::random_32bit_uinteger()
      % files_names.size());
    base::decode_from_hex(files_names[randindex], *key);
  }
  return LoadChunk(*key, value);
}

bool ChunkStore::DeleteChunk(const std::string &key) {
  if (!init_) {
#ifdef DEBUG
    printf("No init in ChunkStore::DeleteChunk.\n");
#endif
    return false;
  }
  fs::path filename(GetPathFromKey(key));
  if (!fs::exists(filename)) {
#ifdef DEBUG
    printf("File in ChunkStore::DeleteChunk.\n");
#endif
    return true;
  }
  try {
    fs::remove(filename);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Couldn't remove file in ChunkStore::DeleteChunk.\n");
    printf("%s\n", e.what());
#endif
    return false;
  }
  return (!fs::exists(filename));
}

void ChunkStore::GetAllChunks(std::list<std::string> *chunk_names) {
  if (!init_)
    return;
  chunk_names->clear();
  fs::directory_iterator end_itr;
  for (fs::directory_iterator itr(chunkstore_dir_); itr != end_itr; ++itr) {
    if (!fs::is_directory(itr->path())) {
      std::string dec_key;
      base::decode_from_hex(itr->path().filename(), dec_key);
      chunk_names->push_back(dec_key);
    }
  }
}

fs::path ChunkStore::GetPathFromKey(const std::string &key) {
  std::string enc_key;
  base::encode_to_hex(key, enc_key);
  fs::path filename(chunkstore_dir_, fs::native);
  filename /= enc_key;
  return filename;
}

int ChunkStore::HashCheckChunk(const std::string &key) {
  if (!init_)
    return -1;
  fs::path filepath_(GetPathFromKey(key));
  if (!fs::exists(filepath_))
    return -1;
  return HashCheckChunk(filepath_);
}

int ChunkStore::HashCheckChunk(const fs::path &filepath) {
  std::string file_hash_ = crypto_.Hash(filepath.string(),
                                        "",
                                        crypto::FILE_STRING,
                                        true);
  if (file_hash_ == filepath.filename())
    return 0;
  else
    return -1;
}

int ChunkStore::HashCheckAllChunks(bool delete_failures,
                                   std::list<std::string> *failed_keys) {
  if (!init_)
    return -1;
  failed_keys->clear();
  try {
    fs::directory_iterator end_itr_;
    for (fs::directory_iterator itr_(chunkstore_dir_);
         itr_ != end_itr_;
         ++itr_) {
      if (!fs::is_directory(itr_->path())) {
        if (HashCheckChunk(itr_->path()) != 0) {
          std::string key_;
          base::decode_from_hex(itr_->path().filename(), key_);
          failed_keys->push_back(key_);
          if (delete_failures)
            fs::remove(itr_->path());
        }
      }
    }
  }
  catch(const std::exception &ex_) {
#ifdef DEBUG
    printf("%s\n", ex_.what());
#endif
    return -1;
  }
  return 0;
}

}  // namespace maidsafe_vault
