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

#include "maidsafe/client/sehandler.h"

#include <boost/filesystem/fstream.hpp>
#include <vector>

#include "maidsafe/utils.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

SEHandler::SEHandler() : storem_(), client_chunkstore_(), ss_(),
                         uptodate_datamaps_(), connection_to_chunk_uploads_(),
                         pending_chunks_(), file_status_() {}

SEHandler::~SEHandler() { connection_to_chunk_uploads_.disconnect(); }

void SEHandler::Init(boost::shared_ptr<StoreManagerInterface> storem,
                     boost::shared_ptr<ChunkStore> client_chunkstore) {
  uptodate_datamaps_.clear();
  pending_chunks_.clear();
  ss_ = SessionSingleton::getInstance();
  storem_ = storem;
  client_chunkstore_ = client_chunkstore;
  connection_to_chunk_uploads_ =
      storem_->ConnectToOnChunkUploaded(boost::bind(&SEHandler::ChunkDone,
                                                    this, _1, _2));
}

ItemType SEHandler::CheckEntry(const fs::path &full_path,
                               boost::uint64_t *file_size,
                               std::string *file_hash) {
  *file_size = 0;
  file_hash->clear();
  // TODO(Fraser#5#): 2010-03-08 - Change 245 below for constant
  if (full_path.string().size() > 245) {
#ifdef DEBUG
    printf("File name too long to process: %s\n", full_path.string().c_str());
#endif
    return NOT_FOR_PROCESSING;
  }
  bool exists(false);
  bool is_directory(false);
  bool is_symlink(false);
  bool is_regular(false);
  bool is_empty(false);
  try {
    exists = fs::exists(full_path);
    is_directory = fs::is_directory(full_path);
    is_symlink = fs::is_symlink(full_path);
    is_regular = fs::is_regular(full_path);
    is_empty = fs::is_empty(full_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("In SEHandler::CheckEntry, %s\n", e.what());
#endif
    return UNKNOWN;
  }

  if (!is_directory && !is_symlink && is_regular && exists) {
    try {
      std::ifstream test;
      test.open(full_path.string().c_str(), std::ifstream::binary);
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
    if (StringToLowercase(fs::extension(full_path)) == ".lnk" || is_symlink)
      return LINK;

    *file_size = fs::file_size(full_path);
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    *file_hash = co.Hash(full_path.string(), "", crypto::FILE_STRING, false);
    if (full_path.filename() == base::EncodeToHex(*file_hash)) {
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
}  // end CheckEntry

int SEHandler::EncryptFile(const std::string &rel_entry,
                           const DirType &dir_type,
                           const std::string &msid) {
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string full_entry(file_system::FullMSPathFromRelPath(rel_entry,
                         ss_->SessionName()).string());

  boost::uint64_t file_size(0);
  std::string file_hash;
  ItemType item_type = CheckEntry(full_entry, &file_size, &file_hash);
  DataMap dm, dm_retrieved;
  std::string ser_dm_retrieved, ser_dm, ser_mdm, dir_key;
  SelfEncryption se(client_chunkstore_);
  switch (item_type) {
    // case DIRECTORY:
    // case EMPTY_DIRECTORY:
    //   GenerateUniqueKey(dir_key_);
    //   break;
    case EMPTY_FILE:
      dm.set_file_hash(file_hash);
      dm.SerializeToString(&ser_dm);
      break;
    case REGULAR_FILE:
    case SMALL_FILE:
      // Try to get DM for this file.  If NULL return or file_hash
      // different, then encrypt.
      if (dah->GetDataMap(rel_entry, &ser_dm_retrieved) == kSuccess)
        dm_retrieved.ParseFromString(ser_dm_retrieved);
      if (ser_dm_retrieved.empty() || dm_retrieved.file_hash() != file_hash) {
        dm.set_file_hash(file_hash);
        if (se.Encrypt(full_entry, false, &dm) != kSuccess)
          return -2;
            // insert chunkname with
        StoreChunks(dm, dir_type, msid, rel_entry);
        dm.SerializeToString(&ser_dm);
      }
      break;
    case LOCKED_FILE:
#ifdef DEBUG
      printf("Can't encrypt: file Locked.\n");
#endif
      return -6;
    case LINK:
#ifdef DEBUG
      printf("Can't encrypt: entry is a link.\n");
#endif
      return -7;
    case MAIDSAFE_CHUNK:
#ifdef DEBUG
      printf("Can't encrypt: entry is a maidsafe chunk.\n");
#endif
      return -8;
    case NOT_FOR_PROCESSING:
#ifdef DEBUG
      printf("Can't encrypt: file not for processing.\n");
#endif
      return -9;
    case UNKNOWN:
#ifdef DEBUG
      printf("Can't encrypt: unknown file type.\n");
#endif
      return -10;
    default:
#ifdef DEBUG
      printf("Can't encrypt.\n");
#endif
      return -11;
  }

  if (!ProcessMetaData(rel_entry, item_type, file_hash, file_size, &ser_mdm))
    return -12;
  if (dah->AddElement(rel_entry, ser_mdm, ser_dm, dir_key, true) != kSuccess) {
    return -500;
  }
  return 0;
}

int SEHandler::EncryptString(const std::string &data, std::string *ser_dm) {
  if (data.empty())
    return -8;
  maidsafe::DataMap dm;
  SelfEncryption se(client_chunkstore_);
  ser_dm->clear();
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  dm.set_file_hash(co.Hash(data, "", crypto::STRING_STRING, false));
  if (se.Encrypt(data, true, &dm))
    return -2;

  StoreChunks(dm, PRIVATE, "");
  if (!dm.SerializeToString(ser_dm)) {
#ifdef DEBUG
    printf("SEHandler::EncryptString - Failed to serialize dm\n");
#endif
    return -23;
  }
  return 0;
}

bool SEHandler::ProcessMetaData(const std::string &rel_entry,
                                const ItemType &type,
                                const std::string &hash,
                                const boost::uint64_t &file_size,
                                std::string *ser_mdm) {
  fs::path ms_rel_path(rel_entry);
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(ms_rel_path.filename());
  mdm.set_type(type);
  mdm.set_file_size_high(0);
  mdm.set_file_size_low(0);

  switch (type) {
    case REGULAR_FILE:
    case SMALL_FILE:
      // file_size_ = fs::file_size(full_path_);
      // mdm.set_file_size_high(file_size_/4294967295);
      // mdm.set_file_size_low(file_size_%4294967295);
      mdm.set_file_size_low(static_cast<boost::uint32_t>(file_size));
      // no break as we want file hash added
    case EMPTY_FILE:
      mdm.add_file_hash(hash);
      break;
    case DIRECTORY:
    case EMPTY_DIRECTORY:
      break;
    default:
      return false;
  }
  mdm.SerializeToString(ser_mdm);
  return true;
}  // end ProcessMetaData

int SEHandler::DecryptFile(const std::string &rel_entry) {
#ifdef DEBUG
  // printf("Decrypting: %s\n", entry);
#endif
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string ser_dm;
  // if we don't get DM, this is a directory and cannot be decrypted
  if (dah->GetDataMap(rel_entry, &ser_dm) == kSuccess) {
    //  Get full path
    fs::path full_path(fs::system_complete(
        file_system::FullMSPathFromRelPath(rel_entry, ss_->SessionName())));
    std::string decrypted_path(full_path.string());

    fs::path ms_path(file_system::MaidsafeHomeDir(ss_->SessionName()));
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
    DataMap dm;
    dm.ParseFromString(ser_dm);
    int n = LoadChunks(dm);
    if (n != 0) {
#ifdef DEBUG
      printf("Failed to get all chunks.\n");
#endif
      return -1;
    }
    SelfEncryption se(client_chunkstore_);
    if (se.Decrypt(dm, decrypted_path, 0, false) == kSuccess)
      return 0;
    else
      return -1;
  }
  return -2;
}

int SEHandler::DecryptString(const std::string &ser_dm,
                             std::string *dec_string) {
  DataMap dm;
  dec_string->clear();
  if (!dm.ParseFromString(ser_dm)) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to parse into DM.\n");
#endif
    return -1;
  }
  if (LoadChunks(dm) != 0) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to get all chunks.\n");
#endif
    return -1;
  }
  SelfEncryption se(client_chunkstore_);
  if (se.Decrypt(dm, 0, dec_string)) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to decrypt.\n");
#endif
    return -1;
  }
  return 0;
}

bool SEHandler::MakeElement(const std::string &rel_entry,
                            const ItemType &type,
                            const std::string &directory_key) {
  std::string ser_mdm, ser_dm, dir_key(directory_key);
  if (!ProcessMetaData(rel_entry, type, "", 0, &ser_mdm)) {
#ifdef DEBUG
    printf("Didn't process metadata.\n");
#endif
    return false;
  }
  if (type == EMPTY_DIRECTORY) {
    if (dir_key.empty())
      GenerateUniqueKey(&dir_key);
  } else if (type == EMPTY_FILE) {
    DataMap dm;
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    dm.set_file_hash(co.Hash("", "", crypto::STRING_STRING, false));
    dm.SerializeToString(&ser_dm);
  } else {
#ifdef DEBUG
    printf("Type not recognised in SEHandler::MakeElement.\n");
#endif
    return false;
  }
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  if (!dah->AddElement(rel_entry, ser_mdm, ser_dm, dir_key, true)) {
    // ie AddElement succeeded
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
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  int count(0);
  for (; count < kMaxAttempts; ++count) {
    std::string random_string = base::RandomString(200);
    *key = co.Hash(random_string, "", crypto::STRING_STRING, false);
    if (storem_->KeyUnique(*key, false))
      break;
  }
  return (count < 5) ? 0 : -1;
}

int SEHandler::GetDirKeys(const std::string &dir_path, const std::string &msid,
                          std::string *key, std::string *parent_key) {
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string tidy_path = TidyPath(dir_path);
  fs::path dir(tidy_path, fs::native);
  // Get dir key for dir_path
  if (0 != dah->GetDirKey(dir.string(), key))
    return -1;
  // Get dir key of parent folder.  If msid != "", set it to hash(msid pub_key)
  if (msid == "") {
#ifdef DEBUG
//    printf("No keys needed because Shares/Private is not private itself.\n");
#endif
    if (0 != dah->GetDirKey(dir.parent_path().string(), parent_key))
      return -1;
  } else {
#ifdef DEBUG
    printf("Keys needed because inside of Shares/Private.\n");
#endif
    std::string private_key;
    if (0 != ss_->GetShareKeys(msid, parent_key, &private_key))
      return -1;
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    *parent_key = co.Hash(*parent_key, "", crypto::STRING_STRING, false);
  }
  return 0;
}

int SEHandler::EncryptDb(const std::string &dir_path, const DirType &dir_type,
                         const std::string &dir_key, const std::string &msid,
                         const bool &encrypt_dm, DataMap *dm) {
  std::string ser_dm, enc_dm, db_path;
  SelfEncryption se(client_chunkstore_);
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path, CREATE, &db_path);
  try {
    if (!fs::exists(db_path))
      return -2;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SEHandler::EncryptDb - Can't check DB path\n");
#endif
      return -2;
  }
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string file_hash(co.Hash(db_path, "", crypto::FILE_STRING, false));

  // when encrypting root db and keys db (during logout), GetDbPath fails above,
  // so insert alternative value for file hashes.
  if (file_hash.empty())
    file_hash = co.Hash(db_path, "", crypto::STRING_STRING, false);
  dm->set_file_hash(file_hash);
  if (se.Encrypt(db_path, false, dm) != 0) {
    return -1;
  }
  StoreChunks(*dm, dir_type, msid);
  dm->SerializeToString(&ser_dm);
  if (encrypt_dm)
    EncryptDm(dir_path, ser_dm, msid, &enc_dm);
  else
    enc_dm = ser_dm;

  std::map<std::string, std::string>::iterator it;
  it = uptodate_datamaps_.find(dir_path);
  if (it != uptodate_datamaps_.end()) {
    if (it->second != enc_dm) {
      uptodate_datamaps_.erase(it);
    }
  }
  uptodate_datamaps_.insert(
      std::pair<std::string, std::string>(dir_path, enc_dm));

  if (dir_key == "") {  // Means we're not storing to DHT - used by client
                        // controller to get root dbs for adding to DataAtlas.
#ifdef DEBUG
//    printf("dm is not stored in kademlia.\n");
#endif
//    if (dir_type == ANONYMOUS) {
//      *ser_dm = enc_dm_;
//    } else {
//      std::string ser_gp = CreateDataMapPacket(enc_dm_, dir_type, msid);
//      *ser_dm = ser_gp;
//    }
    return 0;
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
  storem_->StorePacket(dir_key, enc_dm, PD_DIR, dir_type, msid, kOverwrite,
                       functor);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kPendingResult)
      cond_var.wait(lock);
  }
  return result;
#ifdef DEBUG
//   printf("SEHandler::EncryptDb dir_path(%s) succeeded.\n", dir_path.c_str());
#endif
//  return 0;
//  } else {
#ifdef DEBUG
//    printf("SEHandler::EncryptDb dir_path(%s) failed.\n", dir_path.c_str());
#endif
//    return -1;
}

int SEHandler::DecryptDb(const std::string &dir_path, const DirType &dir_type,
                         const std::string &ser_dm, const std::string &dir_key,
                         const std::string &msid, bool dm_encrypted,
                         bool overwrite) {
  std::string ser_dm_loc, enc_dm_loc;
  // get dm from DHT
  if (ser_dm == "") {
    std::vector<std::string> packet_content;
    int result = storem_->LoadPacket(dir_key, &packet_content);
    if (result != kSuccess || packet_content.empty() ||
        packet_content[0].empty()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Enc dm is empty.\n");
#endif
      return -1;
    }
    enc_dm_loc = packet_content[0];
    std::map<std::string, std::string>::iterator it;
    it = uptodate_datamaps_.find(dir_path);

    if (it != uptodate_datamaps_.end()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Found dir_path in set.\n");
#endif
      if (dm_encrypted) {
        if (it->second == enc_dm_loc) {
#ifdef DEBUG
          printf("SEHandler::DecryptDb: Found enc DM in set. ");
          printf("No need to go get it from the network.\n");
#endif
          return 0;
        }
      } else {
        if (it->second == ser_dm) {
#ifdef DEBUG
          printf("SEHandler::DecryptDb: Found ser DM in set. ");
          printf("No need to go get it from the network.\n");
#endif
          return 0;
        }
      }
    } else {
#ifdef DEBUG
      printf("SEHandler::DecryptDb: DIDN'T find dir_path in set.\n");
#endif
    }

    if (dir_type != ANONYMOUS) {
      GenericPacket gp;
      if (!gp.ParseFromString(enc_dm_loc)) {
#ifdef DEBUG
        printf("Failed to parse generic packet.\n");
#endif
        return -1;
      }
      enc_dm_loc = gp.data();
      if (enc_dm_loc == "") {
#ifdef DEBUG
        printf("Enc dm is empty.\n");
#endif
      }
    }
    if (dm_encrypted) {
#ifdef DEBUG
      printf("Decrypting dm.\n");
#endif
      int n = DecryptDm(dir_path, enc_dm_loc, msid, &ser_dm_loc);
#ifdef DEBUG
      printf("Decrypted dm.\n");
#endif
      if (n != 0 || ser_dm_loc == "") {
#ifdef DEBUG
        printf("Died decrypting dm.\n");
#endif
        return -1;
      }

    } else {
      ser_dm_loc = enc_dm_loc;
    }
  } else {
    if (dir_type != ANONYMOUS) {
      GenericPacket gp;
      if (!gp.ParseFromString(ser_dm)) {
#ifdef DEBUG
        printf("Failed to parse generic packet.\n");
#endif
        return -1;
      }
      enc_dm_loc = gp.data();
      if (enc_dm_loc == "") {
#ifdef DEBUG
        printf("Enc dm is empty.\n");
#endif
        return -1;
      }
    } else {
      enc_dm_loc = ser_dm;
    }
    enc_dm_loc = ser_dm;
    if (dm_encrypted) {
#ifdef DEBUG
      printf("Decrypting dm.\n");
#endif
      int n = DecryptDm(dir_path, enc_dm_loc, msid, &ser_dm_loc);
      if (n != 0 || ser_dm_loc == "") {
#ifdef DEBUG
        printf("Died decrypting dm.\n");
#endif
        return -1;
      }
    } else {
      ser_dm_loc = enc_dm_loc;
    }
  }

  DataMap dm;
  if (!dm.ParseFromString(ser_dm_loc)) {
#ifdef DEBUG
    printf("Doesn't parse as a dm.\n");
#endif
    return -1;
  }
  std::string db_path;
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path, CREATE, &db_path);

  int n = LoadChunks(dm);
  if (n != 0) {
#ifdef DEBUG
    printf("Failed to get all chunks.\n");
#endif
    return -1;
  }

  SelfEncryption se(client_chunkstore_);
  if (se.Decrypt(dm, db_path, 0, overwrite)) {
#ifdef DEBUG
    printf("Failed to self decrypt.\n");
#endif
    return -1;
  } else {
    if (dm_encrypted) {
      uptodate_datamaps_.insert(
        std::pair<std::string, std::string>(dir_path, enc_dm_loc));
    } else {
      uptodate_datamaps_.insert(
        std::pair<std::string, std::string>(dir_path, ser_dm));
    }
    return 0;
  }
}

int SEHandler::EncryptDm(const std::string &dir_path, const std::string &ser_dm,
                         const std::string &msid, std::string *enc_dm) {
  std::string key, parent_key, enc_hash, xor_hash, xor_hash_extended;
  // The following function sets parent_key_ to SHA512 hash of MSID public key
  // if msid != "" otherwise it sets it to the dir key of the parent folder
  GetDirKeys(dir_path, msid, &key, &parent_key);

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  enc_hash = co.Hash(parent_key + key, "", crypto::STRING_STRING, false);
  xor_hash = co.Hash(key + parent_key, "", crypto::STRING_STRING, false);

  while (xor_hash_extended.size() < ser_dm.size())
    xor_hash_extended.append(xor_hash);
  xor_hash_extended = xor_hash_extended.substr(0, ser_dm.size());
  crypto::Crypto encryptor;
  encryptor.set_symm_algorithm(crypto::AES_256);
  *enc_dm = encryptor.SymmEncrypt(encryptor.Obfuscate(ser_dm, xor_hash_extended,
                                                      crypto::XOR),
                                  "", crypto::STRING_STRING, enc_hash);
  return 0;
}

int SEHandler::DecryptDm(const std::string &dir_path, const std::string &enc_dm,
                         const std::string &msid, std::string *ser_dm) {
  std::string key, parent_key, enc_hash, xor_hash, xor_hash_extended,
              intermediate;
  // The following function sets parent_key_ to SHA512 hash of MSID public key
  // if msid != "" otherwise it sets it to the dir key of the parent folder
  int n = GetDirKeys(dir_path, msid, &key, &parent_key);

  if (n != 0) {
#ifdef DEBUG
    printf("Error getting dir keys in SEHandler::DecryptDm.\n");
#endif
    return -1;
  }

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  enc_hash = co.Hash(parent_key + key, "", crypto::STRING_STRING, false);
  xor_hash = co.Hash(key + parent_key, "", crypto::STRING_STRING, false);

  crypto::Crypto decryptor;
  decryptor.set_symm_algorithm(crypto::AES_256);
  intermediate = decryptor.SymmDecrypt(enc_dm, "", crypto::STRING_STRING,
                                       enc_hash);
  while (xor_hash_extended.size() < intermediate.size())
    xor_hash_extended.append(xor_hash);
  xor_hash_extended = xor_hash_extended.substr(0, intermediate.size());

  *ser_dm = decryptor.Obfuscate(intermediate, xor_hash_extended, crypto::XOR);
  if (ser_dm->empty()) {
#ifdef DEBUG
    printf("Error decrypting in SEHandler::DecryptDm.\n");
#endif
    return -1;
  }
  return 0;
}

int SEHandler::LoadChunks(const DataMap &dm) {
  int chunks_found(0);
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i) {
    std::string data;
    int n = storem_->LoadChunk(dm.encrypted_chunk_name(i), &data);
#ifdef DEBUG
//    printf("SEHandler::LoadChunks %d of %d, chunk(%s): result(%d)\n",
//           i + 1, dm.encrypted_chunk_name_size(),
//           HexSubstr(dm.encrypted_chunk_name(i)).c_str(), n);
#endif
    chunks_found += n;
    SelfEncryption se(client_chunkstore_);
    fs::path chunk_path = se.GetChunkPath(dm.encrypted_chunk_name(i));
    fs::ofstream ofs;
    ofs.open(chunk_path, std::ios_base::binary);
    ofs << data;
    ofs.close();
  }

  return chunks_found;
}

void SEHandler::StoreChunks(const DataMap &dm, const DirType &dir_type,
                            const std::string &msid, const std::string &path) {
  bool into_map(path.empty() ? false : true);
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i) {
    storem_->StoreChunk(dm.encrypted_chunk_name(i), dir_type, msid);
    if (into_map) {
      PendingChunks pc(dm.encrypted_chunk_name(i), path, msid);
      std::pair<PendingChunksSet::iterator, bool> p =
          pending_chunks_.insert(pc);
      if (!p.second) {
#ifdef DEBUG
        printf("SEHandler::StoreChunks - Something really fucking wrong is "
               "going on in SEHandler with the multi-index for pending "
               "chunks.\n");
#endif
      }
    }
  }
}

int SEHandler::RemoveKeyFromUptodateDms(const std::string &key) {
  std::map<std::string, std::string>::iterator it;
  it = uptodate_datamaps_.find(key);
  if (it != uptodate_datamaps_.end())
    uptodate_datamaps_.erase(it);
  else
    return -1;
  return 0;
}

void SEHandler::PacketOpCallback(const int &store_manager_result,
                                 boost::mutex *mutex,
                                 boost::condition_variable *cond_var,
                                 int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

void SEHandler::ChunkDone(const std::string &chunkname,
                          maidsafe::ReturnCode rc) {
  boost::mutex::scoped_lock loch_sloy(chunkmap_mutex_);
  PCSbyName &chunkname_index = pending_chunks_.get<by_chunkname>();
  PCSbyName::iterator it = chunkname_index.find(chunkname);
  if (it == chunkname_index.end()) {
#ifdef DEBUG
    printf("SEHandler::ChunkDone - No record of the chunk %s\n",
           chunkname.c_str());
    return;
#endif
  }

  PendingChunks pc = *it;
  PCSbyPath &path_index = pending_chunks_.get<by_path>();
  PCSbyPath::iterator path_it = path_index.find(pc.path);
  if (rc == kSuccess) {
    pc.done = rc;
    chunkname_index.replace(it, pc);
    // Check if all others are done
    if (path_it == path_index.end()) {
  #ifdef DEBUG
      printf("SEHandler::ChunkDone - No record of the chunk based on file path"
             " %s and that's even worse since we just put one in. LOL. WTF!\n",
             pc.path.c_str());
      return;
  #endif
    }

    int total(0), pend(0);
    for (; path_it != path_index.end(); ++path_it) {
      if ((*path_it).done == kPendingResult) {
        ++pend;
      }
      ++total;
    }
    if (pend == 0) {
      // Erase traces of the file
      path_it = path_index.find(pc.path);
      path_index.erase(path_it, path_index.end());

      // Notify we're done with this file
      file_status_(pc.path, 100);
    } else {
      // Notify percentage

    }
  } else {
    // TODO(Team#5#): 2010-08-19 - Need to define a proper limit for this
    if (pc.tries < 1) {
      ++pc.tries;
      storem_->StoreChunk(pc.chunkname, pc.dirtype, pc.msid);
    } else {
      // We need to cancel all the other chunks here because it's all
      // pointless. Hopefully we'll have some way of recovering payment from
      // already uploaded chunks.

      // Delete all entries for this path
      path_index.erase(path_it, path_index.end());

      // Signal to notify upload for this is buggered
      file_status_(pc.path, -1);
    }
  }
}

bs2::connection SEHandler::ConnectToOnFileNetworkStatus(
      const OnFileNetworkStatus::slot_type &slot) {
  return file_status_.connect(slot);
}

}  // namespace maidsafe
