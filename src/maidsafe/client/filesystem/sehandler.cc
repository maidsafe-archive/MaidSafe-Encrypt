/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handler for self-encryption/decryption operations - an
*               interface between the clientcontroller and selfencryption
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

#include "maidsafe/client/filesystem/sehandler.h"

#include <boost/filesystem/fstream.hpp>
#include <boost/tr1/memory.hpp>
#include <maidsafe/encrypt/selfencryption.h>

#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/client/filesystem/dataatlashandler.h"
#include "maidsafe/client/clientutils.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

SEHandler::SEHandler() : store_manager_(), client_chunkstore_(),
                         session_singleton_(), up_to_date_datamaps_(),
                         pending_chunks_(), up_to_date_datamaps_mutex_(),
                         chunkmap_mutex_(), connection_to_chunk_uploads_(),
                         file_status_(), path_count_(0), file_added_() {}

SEHandler::~SEHandler() {
  bool pendings_done(false);
  while (!pendings_done) {
    {
      boost::mutex::scoped_lock loch_etive(chunkmap_mutex_);
      pendings_done = pending_chunks_.empty();
//      printf("%d SEH size\n", pending_chunks_.size());
//      PCSbyName &chunkname_index = pending_chunks_.get<by_chunkname>();
//      PCSbyName::iterator it = chunkname_index.begin();
//      while (it != chunkname_index.end()) {
//        printf("%d\n", (*it).count);
//        ++it;
//      }
    }
    if (!pendings_done)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  connection_to_chunk_uploads_.disconnect();
}

void SEHandler::Init(boost::shared_ptr<StoreManagerInterface> storem,
                     boost::shared_ptr<ChunkStore> client_chunkstore) {
  up_to_date_datamaps_mutex_.lock();
  up_to_date_datamaps_.clear();
  up_to_date_datamaps_mutex_.unlock();
  chunkmap_mutex_.lock();
  pending_chunks_.clear();
  chunkmap_mutex_.unlock();
  session_singleton_ = SessionSingleton::getInstance();
  store_manager_ = storem;
  client_chunkstore_ = client_chunkstore;
  if (!connection_to_chunk_uploads_.connected())
    connection_to_chunk_uploads_ =
        store_manager_->ConnectToOnChunkUploaded(boost::bind(&SEHandler::ChunkDone,
                                                      this, _1, _2));
}

ItemType SEHandler::CheckEntry(const fs::path &absolute_path,
                               boost::uint64_t *file_size,
                               std::string *file_hash) {
  *file_size = 0;
  file_hash->clear();
  if (absolute_path.string().size() > kMaxPath) {
#ifdef DEBUG
    printf("File name too long to process: %s\n",
           absolute_path.string().c_str());
#endif
    return NOT_FOR_PROCESSING;
  }
  bool exists(false);
  bool is_directory(false);
  bool is_symlink(false);
  bool is_regular(false);
  bool is_empty(false);
  try {
    exists = fs::exists(absolute_path);
    is_directory = fs::is_directory(absolute_path);
    is_symlink = fs::is_symlink(absolute_path);
    is_regular = fs::is_regular_file(absolute_path);
    is_empty = fs::is_empty(absolute_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("In SEHandler::CheckEntry, %s\n", e.what());
#endif
    return UNKNOWN;
  }

  if (!is_directory && !is_symlink && is_regular && exists) {
    try {
      fs::ifstream test(absolute_path.string().c_str(), fs::ifstream::binary);
      if (!test.good())
        return LOCKED_FILE;
      test.close();
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In SEHandler::CheckEntry, %s\n", e.what());
#endif
      return LOCKED_FILE;
    }
    // TODO(Fraser#5#): 2010-03-08 - This fails in Windows - fix.
    if (StringToLowercase(absolute_path.extension().string()) == ".lnk" ||
        is_symlink)
      return LINK;

    *file_size = fs::file_size(absolute_path);
    *file_hash = SHA512File(absolute_path);
    if (absolute_path.filename().string() == base::EncodeToHex(*file_hash)) {
      *file_size = 0;
      file_hash->clear();
      return MAIDSAFE_CHUNK;
    }
    if (*file_size == 0)
      return EMPTY_FILE;
    if (*file_size < kMinRegularFileSize)
      return SMALL_FILE;
    return REGULAR_FILE;
  } else if (is_directory && !is_symlink && exists) {
    return EMPTY_DIRECTORY;
  }
  return UNKNOWN;
}

int SEHandler::EncryptFile(const fs::path &relative_entry,
                           const DirType &dir_type,
                           const std::string &msid) {
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  fs::path absolute_entry =
      file_system::FullMSPathFromRelPath(relative_entry.string(),
                                         session_singleton_->SessionName());
  boost::uint64_t file_size(0);
  std::string file_hash;
  ItemType item_type = CheckEntry(absolute_entry, &file_size, &file_hash);
  encrypt::DataMap data_map, data_map_retrieved;
  std::string serialised_data_map_retrieved, serialised_data_map;
  std::string serialised_meta_data_map, dir_key;
  switch (item_type) {
    // case DIRECTORY:
    // case EMPTY_DIRECTORY:
    //   GenerateUniqueKey(dir_key_);
    //   break;
    case EMPTY_FILE:
      data_map.set_file_hash(file_hash);
      data_map.SerializeToString(&serialised_data_map);
      break;
    case REGULAR_FILE:
    case SMALL_FILE:
      // Try to get DM for this file.  If NULL return or file_hash
      // different, then encrypt.
      if (dah->GetDataMap(relative_entry.string(),
                          &serialised_data_map_retrieved) == kSuccess) {
        try {
          data_map_retrieved.ParseFromString(serialised_data_map_retrieved);
        }
        catch(const std::exception&) {
          serialised_data_map_retrieved.clear();
        }
      }
      if (serialised_data_map_retrieved.empty() ||
          data_map_retrieved.file_hash() != file_hash) {
        data_map.set_file_hash(file_hash);
        if (encrypt::SelfEncryptFile(absolute_entry, file_system::TempDir(),
                                     &data_map) != kSuccess) {
          return kEncryptFileFailure;
        }
        if (AddChunksToChunkstore(data_map) != kSuccess)
          return kChunkstoreError;
        StoreChunks(data_map, dir_type, msid, relative_entry);
        data_map.SerializeToString(&serialised_data_map);
      }
      break;
    case LOCKED_FILE:
#ifdef DEBUG
      printf("Can't encrypt: file Locked.\n");
#endif
      return kEncryptionLocked;
    case LINK:
#ifdef DEBUG
      printf("Can't encrypt: entry is a link.\n");
#endif
      return kEncryptionLink;
    case MAIDSAFE_CHUNK:
#ifdef DEBUG
      printf("Can't encrypt: entry is a maidsafe chunk.\n");
#endif
      return kEncryptionChunk;
    case NOT_FOR_PROCESSING:
#ifdef DEBUG
      printf("Can't encrypt: file not for processing.\n");
#endif
      return kEncryptionNotForProcessing;
    case UNKNOWN:
#ifdef DEBUG
      printf("Can't encrypt: unknown file type.\n");
#endif
      return kEncryptionUnknownType;
    default:
#ifdef DEBUG
      printf("Can't encrypt.\n");
#endif
      return kGeneralEncryptionError;
  }

  if (!ProcessMetaData(relative_entry, item_type, file_hash, file_size,
                       &serialised_meta_data_map))
    return kEncryptionMDMFailure;
  if (dah->AddElement(relative_entry.string(), serialised_meta_data_map,
                      serialised_data_map, dir_key, true) != kSuccess)
    return kEncryptionDAHFailure;

  return kSuccess;
}

int SEHandler::EncryptString(const std::string &data,
                             std::string *serialised_data_map) {
  if (data.empty())
    return kEncryptionSmallInput;

  encrypt::DataMap data_map;
  serialised_data_map->clear();
  data_map.set_file_hash(SHA512String(data));
  if (encrypt::SelfEncryptString(data, file_system::TempDir(), &data_map) !=
      kSuccess)
    return kEncryptStringFailure;

  if (AddChunksToChunkstore(data_map) != kSuccess)
    return kChunkstoreError;
  StoreChunks(data_map, PRIVATE, "", base::EncodeToHex(data_map.file_hash()));
  if (!data_map.SerializeToString(serialised_data_map)) {
#ifdef DEBUG
    printf("SEHandler::EncryptString - Failed to serialize data_map\n");
#endif
    return kEncryptionDMFailure;
  }
  return 0;
}

bool SEHandler::ProcessMetaData(const fs::path &relative_entry,
                                const ItemType &type,
                                const std::string &hash,
                                const boost::uint64_t &file_size,
                                std::string *serialised_meta_data_map) {
  fs::path ms_relative_path(relative_entry);
  MetaDataMap meta_data_map;
  meta_data_map.set_id(-2);
  meta_data_map.set_display_name(ms_relative_path.filename().string());
  meta_data_map.set_type(type);
  meta_data_map.set_file_size_high(0);
  meta_data_map.set_file_size_low(0);

  switch (type) {
    case REGULAR_FILE:
    case SMALL_FILE:
      // file_size_ = fs::file_size(absolute_path_);
      // meta_data_map.set_file_size_high(file_size_/4294967295);
      // meta_data_map.set_file_size_low(file_size_%4294967295);
      meta_data_map.set_file_size_low(static_cast<boost::uint32_t>(file_size));
      // no break as we want file hash added
    case EMPTY_FILE:
      meta_data_map.add_file_hash(hash);
      break;
    case DIRECTORY:
    case EMPTY_DIRECTORY:
      break;
    default:
      return false;
  }
  meta_data_map.SerializeToString(serialised_meta_data_map);
  return true;
}  // end ProcessMetaData

int SEHandler::DecryptFile(const fs::path &relative_entry) {
#ifdef DEBUG
  // printf("Decrypting: %s\n", entry);
#endif
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string serialised_data_map;
  // if we don't get DM, this is a directory and cannot be decrypted
  if (dah->GetDataMap(relative_entry.string(), &serialised_data_map) !=
      kSuccess) {
    return kEncryptionDAHFailure;
  }

  //  Get full path
  std::string session(session_singleton_->SessionName());
  fs::path absolute_path(fs::system_complete(
      file_system::FullMSPathFromRelPath(relative_entry.string(), session)));
  std::string decrypted_path(absolute_path.string());

  fs::path ms_path(file_system::MaidsafeHomeDir(session));
  fs::path home_path(file_system::HomeDir());

  if (decrypted_path.substr(0, ms_path.string().size()) !=
      ms_path.string()) {
    if (decrypted_path.substr(0, home_path.string().size()) ==
        home_path.string()) {
      decrypted_path.erase(0, home_path.string().size());
      decrypted_path.insert(0, ms_path.string());
    } else {
      std::string root_path = home_path.root_path().string();
      decrypted_path.erase(0, root_path.size());
      decrypted_path.insert(0, ms_path.string());
    }
  }
  encrypt::DataMap data_map;
  data_map.ParseFromString(serialised_data_map);
  std::vector<fs::path> chunk_paths;
  int n = LoadChunks(data_map, &chunk_paths);
  if (n != kSuccess) {
#ifdef DEBUG
    printf("Failed to get all chunks.\n");
#endif
    return kEncryptionSMFailure;
  }
  if (encrypt::SelfDecryptToFile(data_map, chunk_paths, 0, false,
                                 decrypted_path) == kSuccess)
    return kSuccess;
  else
    return kDecryptFileFailure;
}

int SEHandler::DecryptString(const std::string &serialised_data_map,
                             std::string *decrypted_string) {
  encrypt::DataMap data_map;
  decrypted_string->clear();
  if (!data_map.ParseFromString(serialised_data_map)) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to parse into DM.\n");
#endif
    return kEncryptionDMFailure;
  }
  std::vector<fs::path> chunk_paths;
  if (LoadChunks(data_map, &chunk_paths) != kSuccess) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to get all chunks.\n");
#endif
    return kEncryptionSMFailure;
  }
  std::tr1::shared_ptr<std::string> decrypted(new std::string);
  if (encrypt::SelfDecryptToString(data_map, chunk_paths, 0, decrypted) !=
      kSuccess) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to decrypt.\n");
#endif
    return kDecryptStringFailure;
  }
  *decrypted_string = *decrypted;
  return kSuccess;
}

bool SEHandler::MakeElement(const fs::path &relative_entry,
                            const ItemType &type,
                            const std::string &directory_key) {
  std::string serialised_meta_data_map, serialised_data_map;
  std::string dir_key(directory_key);
  if (!ProcessMetaData(relative_entry, type, "", 0,
      &serialised_meta_data_map)) {
#ifdef DEBUG
    printf("Didn't process metadata.\n");
#endif
    return false;
  }
  if (type == EMPTY_DIRECTORY) {
    if (dir_key.empty())
      GenerateUniqueKey(&dir_key);
  } else if (type == EMPTY_FILE) {
    encrypt::DataMap data_map;
    data_map.set_file_hash(SHA512String(""));
    data_map.SerializeToString(&serialised_data_map);
  } else {
#ifdef DEBUG
    printf("Type not recognised in SEHandler::MakeElement.\n");
#endif
    return false;
  }
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  if (dah->AddElement(relative_entry.string(), serialised_meta_data_map,
                      serialised_data_map, dir_key, true) == kSuccess) {
    return true;
  } else {
#ifdef DEBUG
    printf("Didn't add element.\n");
#endif
    return false;
  }
}

int SEHandler::GenerateUniqueKey(std::string *key) {
  const int kMaxAttempts(5);
  int count(0);
  for (; count < kMaxAttempts; ++count) {
    *key = SHA512String(base::RandomString(200));
    if (store_manager_->KeyUnique(*key, false))
      break;
  }
  return (count < 5) ? kSuccess : kEncryptionKeyGenFailure;
}

int SEHandler::GetDirKeys(const fs::path &dir_path,
                          const std::string &msid,
                          std::string *key,
                          std::string *parent_key) {
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string tidy_path = TidyPath(dir_path.string());
  fs::path dir(tidy_path);
  // Get dir key for dir_path
  if (kSuccess != dah->GetDirKey(dir.string(), key))
    return kEncryptionGetDirKeyFailure;
  // Get dir key of parent folder.  If msid != "", set it to hash(msid pub_key)
  if (msid.empty()) {
#ifdef DEBUG
//    printf("No keys needed because Shares/Private is not private itself.\n");
#endif
    if (kSuccess != dah->GetDirKey(dir.parent_path().string(), parent_key))
      return kEncryptionGetDirKeyFailure;
  } else {
#ifdef DEBUG
    printf("Keys needed because inside of Shares/Private.\n");
#endif
    std::string private_key;
    if (kSuccess != session_singleton_->GetShareKeys(msid, parent_key, &private_key))
      return kEncryptionGetDirKeyFailure;
    *parent_key = SHA512String(*parent_key);
  }
  return kSuccess;
}

int SEHandler::EncryptDb(const fs::path &dir_path,
                         const DirType &dir_type,
                         const std::string &dir_key,
                         const std::string &msid,
                         bool encrypt_data_map,
                         encrypt::DataMap *data_map) {
#ifdef DEBUG
  printf("SEHandler::EncryptDb - %s\n", dir_path.string().c_str());
#endif
  std::string serialised_data_map, encrypted_data_map, db_path;
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path.string(), CREATE, &db_path);
  try {
    if (!fs::exists(db_path))
      return kEncryptionDbMissing;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SEHandler::EncryptDb - Can't check DB path - %s\n", e.what());
#endif
    return kEncryptionDbMissing;
  }
  std::string file_hash(SHA512File(db_path));

  // when encrypting root db and keys db (during logout), GetDbPath fails above,
  // so insert alternative value for file hashes.
  if (file_hash.empty())
    file_hash = SHA512String(db_path);
  data_map->set_file_hash(file_hash);
  if (encrypt::SelfEncryptFile(db_path, file_system::TempDir(), data_map) !=
      kSuccess) {
    return kEncryptDbFailure;
  }

  if (encrypt_data_map) {
    std::string this_dir_key, parent_dir_key;
    // The following function sets parent_dir_key to SHA512 hash of MSID public
    // key if msid != "" otherwise it sets it to the dir key of the parent dir.
    if (GetDirKeys(dir_path, msid, &this_dir_key, &parent_dir_key) != kSuccess)
      return kEncryptDbFailure;
    if (encrypt::EncryptDataMap(*data_map, this_dir_key, parent_dir_key,
                                &encrypted_data_map) != kSuccess) {
#ifdef DEBUG
      printf("EncryptDb: Can't encrypt data_map\n");
#endif
      return kEncryptDbFailure;
    }
  } else {
    data_map->SerializeToString(&encrypted_data_map);
  }

  if (AddChunksToChunkstore(*data_map) != kSuccess)
    return kChunkstoreError;

  std::string previous_encrypted_data_map =
      AddToUpToDateDms(dir_key, encrypted_data_map);
  if (previous_encrypted_data_map == encrypted_data_map) {
    file_added_(dir_path.string());
#ifdef DEBUG
    printf("SEHandler::EncryptDb - Found in DMs, whatever that means.\n");
#endif
    file_status_(dir_path.string(), 100);
    return kSuccess;
  }

  StoreChunks(*data_map, dir_type, msid, dir_path);
  if (dir_key.empty()) {  // Means we're not storing to DHT - used by client
                          // controller to get root dbs for adding to DataAtlas.
#ifdef DEBUG
//    printf("data_map is not stored in kademlia.\n");
#endif
//    if (dir_type == ANONYMOUS) {
//      *serialised_data_map = encrypted_data_map_;
//    } else {
//      std::string serialised_gp = CreateDataMapPacket(encrypted_data_map_, dir_type, msid);
//      *serialised_data_map = serialised_gp;
//    }
    return kSuccess;
  }
  ValueType pd_dir_type;
  if (dir_type == ANONYMOUS)
    pd_dir_type = PDDIR_NOTSIGNED;
  else
    pd_dir_type = PDDIR_SIGNED;

  boost::mutex mutex;
  boost::condition_variable cond_var;
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&SEHandler::PacketOpCallback, this, _1,
                                       &mutex, &cond_var, &result);
  if (previous_encrypted_data_map.empty()) {
    store_manager_->StorePacket(dir_key, encrypted_data_map, passport::PD_DIR,
                                dir_type, msid, functor);
  } else {
    store_manager_->UpdatePacket(dir_key, previous_encrypted_data_map,
                                 encrypted_data_map, passport::PD_DIR, dir_type,
                                 msid, functor);
  }
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kPendingResult)
      cond_var.wait(lock);
  }
  return (result == kSuccess) ? kSuccess : kEncryptDbFailure;
}

int SEHandler::DecryptDb(const fs::path &dir_path,
                         const DirType &dir_type,
                         const std::string &encrypted_data_map,
                         const std::string &dir_key,
                         const std::string &msid,
                         bool data_map_encrypted,
                         bool overwrite) {
#ifdef DEBUG
//  printf("SEHandler::DecryptDb - dir_path(%s) type(%i) encrypted(%i) key(%s)",
//         dir_path.string().c_str(), dir_type, data_map_encrypted,
//         HexSubstr(dir_key).c_str());
//  printf(" msid(%s)\n", msid.c_str());
#endif

  std::string retrieved_encrypted_data_map;
  // get data_map from up_to_date_ map or DHT
  if (encrypted_data_map.empty()) {
    std::string current_encrypted_data_map = GetFromUpToDateDms(dir_key);
    if (!GetFromUpToDateDms(dir_key).empty()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Found dir_key; db is up to date.\n");
#endif
      return kSuccess;
    }
    std::vector<std::string> packet_content;
    int result = store_manager_->LoadPacket(dir_key, &packet_content);
    if (result != kSuccess || packet_content.empty() ||
        packet_content[0].empty()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Enc data_map is empty.\n");
#endif
      return kDecryptDbFailure;
    }
    std::string serialised_encrypted_data_map = packet_content[0];
    if (dir_type != ANONYMOUS) {
      GenericPacket gp;
      if (!gp.ParseFromString(serialised_encrypted_data_map)) {
#ifdef DEBUG
        printf("Failed to parse generic packet.\n");
#endif
        return kDecryptDbFailure;
      }
      retrieved_encrypted_data_map = gp.data();
      // TODO(Fraser#5#): 2010-06-28 - Check gp signature is valid
      if (retrieved_encrypted_data_map.empty()) {
#ifdef DEBUG
        printf("Enc data_map is empty.\n");
#endif
        return kDecryptDbFailure;
      }
    }
  } else {
    retrieved_encrypted_data_map = encrypted_data_map;
  }

  encrypt::DataMap data_map;
  if (data_map_encrypted) {
    std::string this_dir_key, parent_dir_key;
    // The following function sets parent_dir_key to SHA512 hash of MSID public
    // key if msid != "" otherwise it sets it to the dir key of the parent dir.
    if (GetDirKeys(dir_path, msid, &this_dir_key, &parent_dir_key) != kSuccess)
      return kDecryptDbFailure;
    if (encrypt::DecryptDataMap(retrieved_encrypted_data_map, this_dir_key,
                                parent_dir_key, &data_map) != kSuccess) {
#ifdef DEBUG
      printf("DecryptDb: Died decrypting data_map.\n");
#endif
      return kDecryptDbFailure;
    }
  } else {
    try {
      data_map.ParseFromString(retrieved_encrypted_data_map);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("DecryptDb: Can't parse data_map - %s\n", e.what());
#endif
      return kDecryptDbFailure;
    }
  }

  std::string db_path;
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path.string(), CREATE, &db_path);

  std::vector<fs::path> chunk_paths;
  int result = LoadChunks(data_map, &chunk_paths);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Failed to get all chunks.\n");
#endif
    return kDecryptDbFailure;
  }

  if (encrypt::SelfDecryptToFile(data_map, chunk_paths, 0, overwrite, db_path)
      != kSuccess) {
#ifdef DEBUG
    printf("Failed to self decrypt.\n");
#endif
    return kDecryptDbFailure;
  } else {
    AddToUpToDateDms(dir_key, retrieved_encrypted_data_map);
    return kSuccess;
  }
}

int SEHandler::LoadChunks(const encrypt::DataMap &data_map,
                          std::vector<fs::path> *chunk_paths) {
  int result(kSuccess);
  for (int i = 0; i < data_map.encrypted_chunk_name_size(); ++i) {
    std::string data;
    int n = store_manager_->LoadChunk(data_map.encrypted_chunk_name(i), &data);
#ifdef DEBUG
//    printf("SEHandler::LoadChunks %d of %d, chunk(%s): result(%d)\n",
//           i + 1, data_map.encrypted_chunk_name_size(),
//           HexSubstr(data_map.encrypted_chunk_name(i)).c_str(), n);
#endif
    if (n != kSuccess)
      result = n;
    else
      chunk_paths->push_back(
          client_chunkstore_->GetChunkPath(data_map.encrypted_chunk_name(i),
                                           (kHashable | kNormal), false));
  }
  return result;
}

//  int SEHandler::AddToChunkStore(
//      const std::map<std::string, fs::path> &to_chunk_store,
//      const fs::path &processing_path,
//      boost::shared_ptr<DataIOHandler> iohandler/*,
//      std::set<std::string> *done_chunks*/) {
//    std::map<std::string, fs::path>::const_iterator it =
//        to_chunk_store.begin();
//    int rc;
//    for (; it != to_chunk_store.end(); ++it) {
//  /********************************************************************/
//  //  rc = client_chunkstore_->AddChunkToOutgoing((*it).first, (*it).second);
//      rc = 0;
//  /********************************************************************/
//
//  //    if (rc == kChunkExistsInChunkstore)
//  //      done_chunks->insert((*it).first);
//    }
//    iohandler->Close();
//    // delete process dir
//    try {
//      if (fs::exists(processing_path))
//        fs::remove_all(processing_path);
//    }
//    catch(const std::exception &e) {
//  #ifdef DEBUG
//      printf("In Encrypt -- %s\n", e.what());
//  #endif
//    }
//    return 0;
//  }

int SEHandler::AddChunksToChunkstore(const encrypt::DataMap &data_map) {
  int result(kSuccess);
  for (int j = 0; j < data_map.encrypted_chunk_name_size(); ++j) {
    // If this succeeds, chunk is moved to chunkstore.  If not, clean up temp.
    fs::path temp_chunk(file_system::TempDir() /
                        base::EncodeToHex(data_map.encrypted_chunk_name(j)));
    int res = client_chunkstore_->AddChunkToOutgoing(
              data_map.encrypted_chunk_name(j), temp_chunk);
    if (res != kSuccess) {
      try {
        fs::remove(temp_chunk);
      }
      catch(const std::exception &e) {
#ifdef DEBUG
        printf("SEHandler::AddChunksToChunkstore: %s\n", e.what());
#endif
      }
      if (res != kChunkExistsInChunkstore)
        result = kChunkstoreError;
    }
  }
  return result;
}

void SEHandler::StoreChunks(const encrypt::DataMap &data_map,
                            const DirType &dir_type,
                            const std::string &msid,
                            const fs::path &path) {
  ChunksToMultiIndex(data_map, msid, path);
  StoreChunksToNetwork(data_map, dir_type, msid);
}

void SEHandler::ChunksToMultiIndex(const encrypt::DataMap &data_map,
                                   const std::string &msid,
                                   const fs::path &path) {
  if (path.empty()) {
#ifdef DEBUG
    printf("SEHandler::StoreChunks - Need summat to index by.\n");
#endif
    return;
  }

  {
    int n(0);
    boost::mutex::scoped_lock loch_eigheach(chunkmap_mutex_);
    for (int i = 0; i < data_map.encrypted_chunk_name_size(); ++i) {
      PendingChunks pc(data_map.encrypted_chunk_name(i), path, msid,
                       path_count_);
      std::pair<PendingChunksSet::iterator, bool> p =
          pending_chunks_.insert(pc);
      if (!p.second) {
#ifdef DEBUG
        printf("SEHandler::StoreChunks - Something really fucking wrong is "
               "going on in SEHandler with the multi-index for pending "
               "chunks.\n");
#endif
      } else {
        ++n;
#ifdef DEBUG
//       printf("SEHandler::StoreChunks: %s - %s - %i\n", path.string().c_str(),
//               base::EncodeToHex(data_map.encrypted_chunk_name(i)).c_str(),
//               path_count_);
#endif
      }
    }
    if (n == data_map.encrypted_chunk_name_size())
      file_added_(path.string());
    else
      printf("SEHandler::StoreChunks: No notification\n");
    ++path_count_;
  }
}

void SEHandler::StoreChunksToNetwork(const encrypt::DataMap &data_map,
                                     const DirType &dir_type,
                                     const std::string &msid) {
  for (int j = 0; j < data_map.encrypted_chunk_name_size(); ++j)
    store_manager_->StoreChunk(data_map.encrypted_chunk_name(j), dir_type,
                               msid);
}

void SEHandler::PacketOpCallback(const int &store_manager_result,
                                 boost::mutex *mutex,
                                 boost::condition_variable *cond_var,
                                 int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

void SEHandler::ChunkDone(const std::string &chunkname, ReturnCode rc) {
#ifdef DEBUG
//  printf("SEHandler::ChunkDone - %s - %d\n",
//         base::EncodeToHex(chunkname).c_str(), rc);
#endif
  boost::mutex::scoped_lock loch_sloy(chunkmap_mutex_);
  PCSbyName &chunkname_index = pending_chunks_.get<by_chunkname>();
  std::pair<PCSbyName::iterator, PCSbyName::iterator> it_cn =
      chunkname_index.equal_range(chunkname);
  if (it_cn.first == it_cn.second) {
#ifdef DEBUG
    printf("SEHandler::ChunkDone - No record of the chunk %s\n",
           base::EncodeToHex(chunkname).c_str());
#endif
    return;
  }

  int count(0);
  fs::path file_path;
  bool found_pending_chunk(false);
  while (it_cn.first != it_cn.second && !found_pending_chunk) {
    if ((*it_cn.first).done == kPendingResult) {
      PendingChunks pc = *it_cn.first;
      count = pc.count;
      file_path = pc.file_path;
      pc.done = rc;
      chunkname_index.replace(it_cn.first, pc);
      found_pending_chunk = true;
    }
    ++it_cn.first;
  }

  if (!found_pending_chunk) {
#ifdef DEBUG
    printf("SEHandler::ChunkDone - No record of the chunk %s needing update\n",
           base::EncodeToHex(chunkname).c_str());
#endif
    return;
  }

  PCSbyPathCount &pathcount_index = pending_chunks_.get<by_path_count>();
  std::pair<PCSbyPathCount::iterator, PCSbyPathCount::iterator> it_pc =
      pathcount_index.equal_range(boost::make_tuple(file_path, count));

  if (it_pc.first == it_pc.second) {
#ifdef DEBUG
    printf("SEHandler::ChunkDone - Well, this is a surprise!\n");
#endif
    return;
  }

  if (rc == kSuccess) {
    int pending(0), finished(0);
    while (it_pc.first != it_pc.second) {
      if ((*it_pc.first).done == kPendingResult) {
        ++pending;
      }
      ++finished;
      ++it_pc.first;
    }

#ifdef DEBUG
//    printf("SEHandler::ChunkDone - %s - %d - %d\n", file_path.string().c_str(),
//           pending, finished);
#endif
    int percentage((finished - pending) * 100 / finished);
    if (pending == 0) {
      it_pc = pathcount_index.equal_range(boost::make_tuple(file_path, count));
      pathcount_index.erase(it_pc.first, it_pc.second);
    }
    file_status_(file_path.string(), percentage);
  } else {
    pathcount_index.erase(it_pc.first, it_pc.second);
    file_status_(file_path.string(), -1);
  }
}

std::string SEHandler::AddToUpToDateDms(const std::string &dir_key,
                                        const std::string &encrypted_data_map) {
  std::string previous_encrypted_data_map;
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  // returns insertion position if dir_key doesn't already exist in map
  UpToDateDatamaps::iterator lb = up_to_date_datamaps_.lower_bound(dir_key);
  if (lb != up_to_date_datamaps_.end() &&
      !(up_to_date_datamaps_.key_comp()(dir_key, lb->first))) {
    // dir_key already exists
    previous_encrypted_data_map = lb->second;
    if (previous_encrypted_data_map != encrypted_data_map)
      lb->second = encrypted_data_map;
  } else {
    // dir_key doesn't exist
    up_to_date_datamaps_.insert(lb, UpToDateDatamaps::value_type(dir_key,
                                                                 encrypted_data_map));
  }
  return previous_encrypted_data_map;
}

std::string SEHandler::GetFromUpToDateDms(const std::string &dir_key) {
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  UpToDateDatamaps::iterator it = up_to_date_datamaps_.find(dir_key);
  return (it == up_to_date_datamaps_.end()) ? "" : (*it).second;
}

int SEHandler::RemoveFromUpToDateDms(const std::string &dir_key) {
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  size_t removed_count = up_to_date_datamaps_.erase(dir_key);
  return removed_count == size_t(1) ? kSuccess : kEncryptionDmNotInMap;
}

bs2::connection SEHandler::ConnectToOnFileNetworkStatus(
    const OnFileNetworkStatus::slot_type &slot) {
  return file_status_.connect(slot);
}

bs2::connection SEHandler::ConnectToOnFileAdded(
    const OnFileAdded::slot_type &slot) {
  return file_added_.connect(slot);
}

}  // namespace maidsafe
