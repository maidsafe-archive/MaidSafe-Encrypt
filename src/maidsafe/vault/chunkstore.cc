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

namespace maidsafe_vault {

ChunkStore::ChunkStore(const std::string &chunkstore_dir)
    : chunkstore_set_(),
      path_map_(),
      kChunkstorePath_(chunkstore_dir),
      is_initialised_(false),
      initialised_mutex_(),
      chunkstore_set_mutex_(),
      kHashableLeaf_("Hashable"),
      kNonHashableLeaf_("NonHashable"),
      kNormalLeaf_("Normal"),
      kCacheLeaf_("Cache"),
      kOutgoingLeaf_("Outgoing"),
      kTempCacheLeaf_("TempCache") {
  boost::thread init_thread(&ChunkStore::Init, this);
}

bool ChunkStore::is_initialised() {
  bool init_result(false);
  {
    boost::mutex::scoped_lock lock(initialised_mutex_);
    init_result = is_initialised_;
  }
  return init_result;
}

void ChunkStore::set_is_initialised(bool value) {
  boost::mutex::scoped_lock lock(initialised_mutex_);
  is_initialised_ = value;
}

bool ChunkStore::Init() {
  if (is_initialised())
      return true;
  if (!PopulatePathMap()) {
    set_is_initialised(false);
    return false;
  }
  chunkstore_set_.clear();
  // Check root directories exist and if not, create them.
  bool temp_result = true;
  try {
    for (path_map_iterator path_map_itr = path_map_.begin();
         path_map_itr != path_map_.end(); ++path_map_itr) {
      if (fs::exists((*path_map_itr).second)) {
        temp_result = temp_result && PopulateChunkSet((*path_map_itr).first,
                                                      (*path_map_itr).second);
//        printf("Found %s\n", (*path_map_itr).second.string().c_str());
      } else {
        temp_result = temp_result &&
            fs::create_directories((*path_map_itr).second);
//        printf("Created %s\n", (*path_map_itr).second.string().c_str());
      }
    }
    set_is_initialised(temp_result);
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("ChunkStore::Init failed.\nException: %s\n", ex.what());
#endif
    set_is_initialised(false);
  }
  return is_initialised();
}

bool ChunkStore::PopulatePathMap() {
  try {
    path_map_iterator path_map_itr;
    fs::path hashable_parent(kChunkstorePath_ / kHashableLeaf_);
    path_map_.insert(std::pair<ChunkType, fs::path>(kHashable | kNormal,
        fs::path(hashable_parent / kNormalLeaf_)));
    path_map_itr = path_map_.begin();
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kHashable | kCache, fs::path(hashable_parent / kCacheLeaf_)));
    ++path_map_itr;
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kHashable | kOutgoing, fs::path(hashable_parent / kOutgoingLeaf_)));
    ++path_map_itr;
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kHashable | kTempCache, fs::path(hashable_parent / kTempCacheLeaf_)));
    ++path_map_itr;
    fs::path non_hashable_parent(kChunkstorePath_ / kNonHashableLeaf_);
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kNonHashable | kNormal, fs::path(non_hashable_parent / kNormalLeaf_)));
    ++path_map_itr;
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kNonHashable | kCache, fs::path(non_hashable_parent / kCacheLeaf_)));
    ++path_map_itr;
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kNonHashable | kOutgoing,
        fs::path(non_hashable_parent / kOutgoingLeaf_)));
    ++path_map_itr;
    path_map_.insert(path_map_itr, std::pair<ChunkType, fs::path>
        (kNonHashable | kTempCache,
        fs::path(non_hashable_parent / kTempCacheLeaf_)));
    if (static_cast<boost::uint32_t>(8) != path_map_.size())
      return false;
    else
      return true;
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("%s\n", ex.what());
#endif
    return false;
  }

}

void ChunkStore::FindFiles(const fs::path &root_dir_path,
                           ChunkType type,
                           bool hash_check,
                           bool delete_failures,
                           boost::uint64_t *filecount,
                           std::list<std::string> *failed_keys) {
  try {
    if (!fs::exists(root_dir_path))
      return;
    std::string non_hex_name("");
    fs::directory_iterator end_itr;
    for (fs::directory_iterator itr(root_dir_path); itr != end_itr; ++itr) {
  //    printf("Iter at %s\n", itr->path().filename().c_str());
      if (fs::is_directory(itr->status())) {
        FindFiles(itr->path(), type, hash_check, delete_failures, filecount,
                  failed_keys);
      } else  {
        ++(*filecount);
        if (base::decode_from_hex(itr->path().filename(), &non_hex_name) &&
            fs::file_size(itr->path()) >= 2) {
          ChunkInfo chunk(non_hex_name,
              boost::posix_time::microsec_clock::local_time(), type);
          {
            boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
            chunkstore_set_.insert(chunk);
          }
          if ((type == (kHashable | kNormal) || type == (kHashable | kCache) ||
              type == (kHashable | kOutgoing) || type == (kHashable | kTempCache))
              && hash_check) {
            if (HashCheckChunk(non_hex_name, itr->path()) != 0) {
              failed_keys->push_back(non_hex_name);
              if (delete_failures) {
                if (DeleteChunkFunction(non_hex_name, itr->path()))
                  --(*filecount);
              }
            }
          }
        }
      }
    }
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("%s\n", ex.what());
#endif
  }
}

bool ChunkStore::PopulateChunkSet(ChunkType type, const fs::path &dir_path) {
  boost::posix_time::ptime now(boost::posix_time::microsec_clock::local_time());
  boost::uint64_t original_size;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    original_size = chunkstore_set_.size();
  }
  boost::uint64_t filecount = 0;
  std::list<std::string> failed_keys;
  FindFiles(dir_path, type, true, true, &filecount, &failed_keys);
//  std::list<std::string>::iterator itr;
//  for (itr = failed_keys.begin(); itr != failed_keys.end(); ++itr) {
//    if (DeleteChunk((*itr)))
//      --filecount;
//  }
  boost::uint64_t current_size;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    current_size = chunkstore_set_.size();
  }
#ifdef DEBUG
//  printf("In ChunkStore::PopulateChunkSet %s, current_size = %llu, "
//         "original_size = %llu, filecount = %llu\n",
//         dir_path.string().c_str(), current_size, original_size, filecount);
#endif
  return ((current_size - original_size) == filecount);
}

bool ChunkStore::HasChunk(const std::string &key) {
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::HasChunk.\n");
#endif
    return false;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::HasChunk, incorrect key size.\n");
#endif
    return false;
  }
  bool result(false);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<non_hex_name>().find(key);
    result = (itr != chunkstore_set_.end());
  }
  return result;
}

ChunkType ChunkStore::GetChunkType(const std::string &key,
                                   const std::string &value) {
  ChunkType type = (kHashable | kNormal);
  bool new_chunk(true);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<non_hex_name>().find(key);
    if (itr != chunkstore_set_.end()) {  // i.e. we have the chunk's details
      new_chunk = false;
      type = (*itr).type_;
    }
  }
  if (!new_chunk)
    return type;
  // otherwise this is a new chunk
  crypto::Crypto crypto;
  crypto.set_hash_algorithm(crypto::SHA_512);
  if (value != "" &&
      key != crypto.Hash(value, "", crypto::STRING_STRING, false))
    type = kNonHashable | kNormal;
  return type;
}

fs::path ChunkStore::GetChunkPath(const std::string &key,
                                  ChunkType type,
                                  bool create_path) {
  path_map_iterator path_map_itr = path_map_.find(type);
  if (path_map_itr == path_map_.end()) {
#ifdef DEBUG
    printf("In ChunkStore::GetChunkPath, %i is not a valid type\n", type);
#endif
    return fs::path("");
  }
  std::string hex_key("");
  base::encode_to_hex(key, &hex_key);
  std::string dir_one, dir_two, dir_three;
  dir_one = hex_key.substr(0, 1);
  dir_two = hex_key.substr(1, 1);
  dir_three = hex_key.substr(2, 1);
  fs::path chunk_path((*path_map_itr).second / dir_one / dir_two / dir_three);
  try {
    if (!fs::exists(chunk_path)) {
      if (create_path) {
          fs::create_directories(chunk_path);
        chunk_path /= hex_key;
      } else {
        chunk_path = fs::path("");
      }
    } else {
      chunk_path /= hex_key;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    chunk_path = fs::path("");
  }
#ifdef DEBUG
//  printf("Chunk path: %s\n\n", chunk_path.string().c_str());
#endif
  return chunk_path;
}

ChunkInfo ChunkStore::GetOldestChecked() {
  ChunkInfo chunk;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_last_checked::iterator itr =
        chunkstore_set_.get<1>().begin();
    chunk = *itr;
  }
  return chunk;
}

bool ChunkStore::StoreChunk(const std::string &key, const std::string &value) {
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::StoreChunk.\n");
#endif
    return false;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::StoreChunk, incorrect key size.\n");
#endif
    return false;
  }
  if (HasChunk(key)) {
#ifdef DEBUG
    printf("Chunk already exists in ChunkStore::StoreChunk.\n");
#endif
    return false;
  }
  ChunkType type = GetChunkType(key, value);
  fs::path chunk_path(GetChunkPath(key, type, true));
  return StoreChunkFunction(key, value, chunk_path, type);
}

bool ChunkStore::StoreChunkFunction(const std::string &key,
                                    const std::string &value,
                                    const fs::path &chunk_path,
                                    ChunkType type) {
  try {
    boost::uint64_t chunk_size(value.size());
    fs::ofstream fstr;
    fstr.open(chunk_path, std::ios_base::binary);
    fstr.write(value.c_str(), chunk_size);
    fstr.close();
    // If the chunk is hashable then set last checked time to now, otherwise
    // set it to max allowable time.
    boost::posix_time::ptime lastcheckedtime(boost::posix_time::max_date_time);
    if (type == (kHashable | kNormal) || type == (kHashable | kCache) ||
        type == (kHashable | kOutgoing) || type == (kHashable | kTempCache)) {
      lastcheckedtime = boost::posix_time::microsec_clock::local_time();
    }
    ChunkInfo chunk(key, lastcheckedtime, type);
    {
      boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
      chunkstore_set_.insert(chunk);
    }
    return true;
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("ChunkStore::StoreChunk exception writing chunk: %s\n", ex.what());
#endif
    return false;
  }
}

bool ChunkStore::DeleteChunk(const std::string &key) {
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::DeleteChunk.\n");
#endif
    return false;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::DeleteChunk, incorrect key size.\n");
#endif
    return false;
  }
  ChunkType type = GetChunkType(key, "");
  fs::path chunk_path(GetChunkPath(key, type, false));
  return DeleteChunkFunction(key, chunk_path);
}

bool ChunkStore::DeleteChunkFunction(const std::string &key,
                                     const fs::path &chunk_path) {
  bool exists(false);
  try {
    exists = fs::exists(chunk_path);
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("ChunkStore::DeleteChunkFunction: %s\n", ex.what());
#endif
    return false;
  }
  if (!exists) {
    {
#ifdef DEBUG
      printf("In ChunkStore::DeleteChunk, file didn't exist.\n");
#endif
      boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
      chunk_set_by_non_hex_name::iterator itr =
          chunkstore_set_.get<non_hex_name>().find(key);
      if (itr != chunkstore_set_.end())  // i.e. we have the chunk's details
        chunkstore_set_.erase(itr);
    }
    return true;
  }
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<non_hex_name>().find(key);
    if (itr != chunkstore_set_.end())  // i.e. we have the chunk's details
      chunkstore_set_.erase(itr);
  }
  // Doesn't matter if we don't actually remove chunk file.
  try {
    fs::remove(chunk_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Couldn't remove file in ChunkStore::DeleteChunk.\n");
    printf("%s\n", e.what());
#endif
  }
  bool result(false);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<non_hex_name>().find(key);
    result = (itr == chunkstore_set_.end());
  }
  return (result);
}

bool ChunkStore::UpdateChunk(const std::string &key, const std::string &value) {
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::UpdateChunk.\n");
#endif
    return false;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::UpdateChunk, incorrect key size.\n");
#endif
    return false;
  }
  // check we have the chunk already
  ChunkType type = 0;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<non_hex_name>().find(key);
    if (itr != chunkstore_set_.end())
      type = (*itr).type_;
  }
  if (type == 0) {
#ifdef DEBUG
    printf("In ChunkStore::UpdateChunk, don't currently have chunk.\n");
#endif
    return false;
  }
  fs::path chunk_path(GetChunkPath(key, type, false));
  if (!DeleteChunkFunction(key, chunk_path))
    return false;
  return StoreChunkFunction(key, value, chunk_path, type);
}

bool ChunkStore::LoadChunk(const std::string &key, std::string *value) {
  value->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::LoadChunk.\n");
#endif
    return false;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::LoadChunk, incorrect key size.\n");
#endif
    return false;
  }
  if (!HasChunk(key))
    return false;
  ChunkType type = GetChunkType(key, "");
  fs::path chunk_path(GetChunkPath(key, type, false));
  boost::uint64_t chunk_size(0);
  try {
    chunk_size = fs::file_size(chunk_path);
    boost::scoped_array<char> temp(new char[chunk_size]);
    fs::ifstream fstr;
    fstr.open(chunk_path, std::ios_base::binary);
    fstr.read(temp.get(), chunk_size);
    fstr.close();
    std::string result(static_cast<const char*>(temp.get()), chunk_size);
    *value = result;
    return true;
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("%s\n", ex.what());
#endif
    return false;
  }
}

bool ChunkStore::LoadRandomChunk(std::string *key, std::string *value) {
  key->clear();
  value->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::LoadRandomChunk.\n");
#endif
    return false;
  }
  bool result(false);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    if (chunkstore_set_.size() != 0)
      result = true;
  }
  if (!result) {
#ifdef DEBUG
    printf("In ChunkStore::LoadRandomChunk: there are no chunks stored.\n");
#endif
    return false;
  }
  ChunkType type = (kHashable | kNormal);
  boost::uint64_t hashable_count(0);
  {
    chunk_set_by_chunk_type &sorted_index = chunkstore_set_.get<chunk_type>();
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    hashable_count = sorted_index.count(type);
  }
  if (!hashable_count)  // i.e. there are no chunks available
    return false;
  int randindex = static_cast<int>(base::random_32bit_uinteger()
      % hashable_count);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_chunk_type::iterator itr =
         chunkstore_set_.get<chunk_type>().begin();
    for (int i = 0; i < randindex; ++i, ++itr) {}
    *key = (*itr).non_hex_name_;
    // check we've got the correct type
    result = ((*itr).type_ == type);
  }
  if (result)
    return LoadChunk(*key, value);
  else
    return false;
}

void ChunkStore::GetAllChunks(std::list<std::string> *chunk_names) {
  chunk_names->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::GetAllChunks.\n");
#endif
    return;
  }
  boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
  for (chunk_set_by_non_hex_name::iterator itr =
       chunkstore_set_.get<non_hex_name>().begin();
       itr != chunkstore_set_.get<non_hex_name>().end(); ++itr) {
    chunk_names->push_back((*itr).non_hex_name_);
  }
}

int ChunkStore::HashCheckChunk(const std::string &key) {
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::HashCheckChunk.\n");
#endif
    return -1;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::HashCheckChunk, incorrect key size.\n");
#endif
    return -1;
  }
  ChunkType type = GetChunkType(key, "");
  fs::path chunk_path(GetChunkPath(key, type, false));
  if (chunk_path == fs::path(""))
    return -1;
  return HashCheckChunk(key, chunk_path);
}

int ChunkStore::HashCheckChunk(const std::string &key,
                               const fs::path &chunk_path) {
  crypto::Crypto crypto;
  crypto.set_hash_algorithm(crypto::SHA_512);
  std::string file_hash = crypto.Hash(chunk_path.string(), "",
                                      crypto::FILE_STRING, false);
  std::string non_hex_filename("");
  boost::posix_time::ptime now(boost::posix_time::microsec_clock::local_time());
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name &non_hex_name_index =
        chunkstore_set_.get<non_hex_name>();
    chunk_set_by_non_hex_name::iterator itr = non_hex_name_index.find(key);
    if (itr == chunkstore_set_.end())
      return -1;
    non_hex_filename = (*itr).non_hex_name_;
    non_hex_name_index.modify(itr, change_last_checked(now));
  }
  return file_hash == non_hex_filename ? 0 : -2;
}

int ChunkStore::HashCheckAllChunks(bool delete_failures,
                                   std::list<std::string> *failed_keys) {
  failed_keys->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::HashCheckAllChunks.\n");
#endif
    return -1;
  }
  boost::uint64_t filecount;
  bool result(true);
  for (path_map_iterator path_map_itr = path_map_.begin();
       path_map_itr != path_map_.end(); ++path_map_itr) {
    ChunkType type = path_map_itr->first;
    if (type == (kHashable | kNormal) || type == (kHashable | kCache) ||
        type == (kHashable | kOutgoing) || type == (kHashable | kTempCache)) {
      FindFiles(path_map_itr->second, type, true, delete_failures, &filecount,
                failed_keys);
    }
  }
  if (delete_failures) {
    std::list<std::string>::iterator itr;
    for (itr = failed_keys->begin(); itr != failed_keys->end(); ++itr) {
      if (DeleteChunk((*itr))) {
        --filecount;
      } else {
        result = false;
      }
    }
  }
  if (!result)
    return -1;
  return 0;
}

int ChunkStore::ChangeChunkType(const std::string &key, ChunkType type) {
  if (!HasChunk(key)) {
#ifdef DEBUG
    printf("In ChunkStore::ChangeChunkType: chunk doesn't exist.\n");
#endif
    return -1;
  }
  ChunkType current_type = GetChunkType(key, "");
  if (current_type == type)
    return 0;
  fs::path current_chunk_path(GetChunkPath(key, current_type, false));
  fs::path new_chunk_path(GetChunkPath(key, type, true));
  if (new_chunk_path == fs::path("")) {
#ifdef DEBUG
    printf("In ChunkStore::ChangeChunkType, %i is not a valid type\n", type);
#endif
    return -1;
  }
  // Try to rename file.  If this fails try to copy.  If this fails, return
  // negative int.
  bool renamed(false);
  try {
    fs::rename(current_chunk_path, new_chunk_path);
    renamed = true;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
  }
  if (!renamed) {
    try {
      fs::copy_file(current_chunk_path, new_chunk_path);
    }
    catch(const std::exception &e) {
  #ifdef DEBUG
      printf("%s\n", e.what());
  #endif
      return -1;
    }
  }
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_non_hex_name &non_hex_name_index =
        chunkstore_set_.get<non_hex_name>();
    chunk_set_by_non_hex_name::iterator itr = non_hex_name_index.find(key);
    non_hex_name_index.modify(itr, change_type(type));
  }
  return 0;
}

}  // namespace maidsafe_vault
