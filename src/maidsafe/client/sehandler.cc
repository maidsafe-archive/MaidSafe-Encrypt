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
#include <boost/scoped_ptr.hpp>
#include <maidsafe/utils.h>

#include <vector>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/privateshares.h"
#include "protobuf/packet.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

SEHandler::SEHandler()
    : storem_(), client_chunkstore_(), ss_(), uptodate_datamaps_() {}

void SEHandler::Init(boost::shared_ptr<StoreManagerInterface> storem,
                     boost::shared_ptr<ChunkStore> client_chunkstore) {
  uptodate_datamaps_.clear();
  ss_ = SessionSingleton::getInstance();
  storem_ = storem;
  client_chunkstore_ = client_chunkstore;
}

ItemType SEHandler::CheckEntry(const std::string &full_entry,
                               boost::uint64_t *file_size) {
  if (full_entry.size()>245) {
#ifdef DEBUG
    printf("File name too long to process: %s\n", full_entry.c_str());
#endif
    return NOT_FOR_PROCESSING;
  }
  fs::path path_(full_entry, fs::native);
  try {
    fs::exists(path_);
    fs::is_directory(path_);
    fs::is_symlink(path_);
    fs::is_regular(path_);
    fs::is_empty(path_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return UNKNOWN;
  }

  if (!fs::is_directory(path_) &&
      !fs::is_symlink(path_) &&
      fs::is_regular(path_) &&
      fs::exists(path_)) {
    // If file size < 2 bytes, it's too small to chunk
    // if (fs::file_size(path_)<2) return SMALL_FILE;
    // leave this up to calling object now !
    // David Irvine<david.irvine@maidsafe.net>  15/09/2008 11:08:38
    // return a number which is the file size enum all else negative
    try {
      std::ifstream test_;
      test_.open(path_.string().c_str(), std::ifstream::binary);
      if (!test_.good())
        return LOCKED_FILE;
      test_.close();
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("%s\n", e.what());
#endif
      return LOCKED_FILE;
    }
    *file_size = fs::file_size(path_);
    if (*file_size == 0) return EMPTY_FILE;
    if (*file_size < kMinRegularFileSize) return SMALL_FILE;
    if (base::StrToLwr(fs::extension(path_)) == ".lnk" ||
        fs::is_symlink(path_))
      return LINK;  // fails in Windows
    return REGULAR_FILE;
  } else if (fs::is_directory(path_) &&
           !fs::is_symlink(path_) &&
           fs::exists(path_)) {
    *file_size = 0;
    return EMPTY_DIRECTORY;
  }
  return UNKNOWN;
}  // end CheckEntry

std::string SEHandler::SHA512(const std::string &full_entry,
                              bool hash_contents) {
  SelfEncryption se(client_chunkstore_);
  if (hash_contents) {
    fs::path entry_path(full_entry, fs::native);
    return se.SHA512(entry_path);
  } else {
    return se.SHA512(full_entry);
  }
}

int SEHandler::EncryptFile(const std::string &rel_entry,
                           const DirType dir_type,
                           const std::string &msid) {
#ifdef DEBUG
  // printf("Encrypting: %s\n", rel_entry.c_str());
#endif
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string full_entry = file_system::FullMSPathFromRelPath(
      rel_entry, ss_->SessionName()).string();

  boost::uint64_t file_size = 0;
  ItemType item_type = CheckEntry(full_entry, &file_size);
  DataMap dm, dm_retrieved;
  std::string ser_dm_retrieved, ser_dm, ser_mdm, file_hash, dir_key;
  SelfEncryption se(client_chunkstore_);
#ifdef DEBUG
  // printf("Full entry: %s\n", full_entry_.c_str());
  // printf("Type: %i\n", type_);
  // printf("File size: %lu\n", file_size_);
#endif
  switch (item_type) {
    // case DIRECTORY:
    // case EMPTY_DIRECTORY:
    //   GenerateUniqueKey(dir_key_);
    //   break;
    case EMPTY_FILE:
      dm.set_file_hash(SHA512(full_entry, true));
      dm.SerializeToString(&ser_dm);
      break;
    case REGULAR_FILE:
    case SMALL_FILE:
      file_hash = SHA512(full_entry, true);
      // Try to get DM for this file.  If NULL return or file_hash
      // different, then encrypt.
      if (dah->GetDataMap(rel_entry, &ser_dm_retrieved) == kSuccess)
        dm_retrieved.ParseFromString(ser_dm_retrieved);
      if (ser_dm_retrieved.empty() || dm_retrieved.file_hash() != file_hash) {
        dm.set_file_hash(file_hash);
        if (se.Encrypt(full_entry, false, &dm) != kSuccess)
          return -2;
        StoreChunks(dm, dir_type, msid);
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
    case NOT_FOR_PROCESSING:
#ifdef DEBUG
      printf("Can't encrypt: file not for processing.\n");
#endif
      return -8;
    case UNKNOWN:
#ifdef DEBUG
      printf("Can't encrypt: unknown file type.\n");
#endif
      return -9;
    default:
#ifdef DEBUG
      printf("Can't encrypt.\n");
#endif
      return -10;
  }

  if (!ProcessMetaData(rel_entry, item_type, file_hash, file_size, &ser_mdm))
    return -11;
  if (dah->AddElement(rel_entry, ser_mdm, ser_dm, dir_key, true) != kSuccess) {
    return -500;
  }
  return 0;
}

int SEHandler::EncryptString(const std::string &data,
                             std::string *ser_dm) {
  if (data.empty())
    return -8;
  maidsafe::DataMap dm;
  SelfEncryption se(client_chunkstore_);
  ser_dm->clear();
  dm.set_file_hash(se.SHA512(data));
  if (se.Encrypt(data, true, &dm))
    return -2;
  StoreChunks(dm, PRIVATE, "");
  dm.SerializeToString(ser_dm);
  return 0;
}

bool SEHandler::ProcessMetaData(const std::string &rel_entry,
                                const ItemType type,
                                const std::string &hash,
                                const boost::uint64_t &file_size,
                                std::string *ser_mdm) {
  // boost::mutex::scoped_lock lock(mutex2_);
  // if parent dir doesn't exist, quit
  // fs::path full_path_(fsys_->MaidsafeHomeDir() / rel_entry);
  fs::path ms_rel_path_(rel_entry);
  // std::string s;
  // if (dah_->GetMetaDataMap(ms_rel_path_.parent_path().string(), s)<0)
  //   // ie mdm not found
  //   return false;
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(ms_rel_path_.filename());
  mdm.set_type(type);
  mdm.set_file_size_high(0);
  mdm.set_file_size_low(0);
  // time_t seconds;
  // seconds = time (NULL);
  // mdm.set_last_modified((int)seconds);
  // mdm.set_last_access((int)seconds);

  switch (type) {
    case REGULAR_FILE:
    case SMALL_FILE:
      // file_size_ = fs::file_size(full_path_);
      // mdm.set_file_size_high(file_size_/4294967295);
      // mdm.set_file_size_low(file_size_%4294967295);
      mdm.set_file_size_low(static_cast<uint32_t>(file_size));
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
    std::string decrypted_path = full_path.string();

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
  dm.ParseFromString(ser_dm);
  if (LoadChunks(dm) != 0)
    return -1;
  SelfEncryption se(client_chunkstore_);
  if (se.Decrypt(dm, 0, dec_string))
    return -1;
  return 0;
}

bool SEHandler::MakeElement(const std::string &rel_entry,
                            const ItemType type,
                            const DirType dir_type,
                            const std::string &msid,
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
      GenerateUniqueKey(dir_type, msid, 0, &dir_key);
  } else if (type == EMPTY_FILE) {
    DataMap dm;
    dm.set_file_hash(SHA512("", false));
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

int SEHandler::GenerateUniqueKey(const DirType,
                                 const std::string &,
                                 const int &attempt,
                                 std::string *key) {
  *key = base::RandomString(200);
  *key = SHA512(*key, false);
  int count = attempt;
  while (!storem_->KeyUnique(*key, false) && count < 5) {
    ++count;
    *key = base::RandomString(200);
    *key = SHA512(*key, false);
  }
  if (count < 5) {
//    ValueType pd_dir_type_;
//    if (dir_type == ANONYMOUS)
//      pd_dir_type_ = PDDIR_NOTSIGNED;
//    else
//      pd_dir_type_ = PDDIR_SIGNED;
//  //    std::string ser_gp = CreateDataMapPacket("temp data", dir_type, msid);
//   return storem_->StorePacket(*key, "a", PD_DIR, dir_type, msid);
    return 0;
  }
  return -1;
}

int SEHandler::GetDirKeys(const std::string &dir_path,
                          const std::string &msid,
                          std::string *key,
                          std::string *parent_key) {
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler);
  std::string tidy_path_ = base::TidyPath(dir_path);
  fs::path dir_(tidy_path_, fs::native);
  // Get dir key for dir_path
  if (0 != dah_->GetDirKey(dir_.string(), key))
    return -1;
  // Get dir key of parent folder.  If msid != "", set it to hash(msid pub_key)
  if (msid == "") {
#ifdef DEBUG
//    printf("No keys needed because Shares/Private is not private itself.\n");
#endif
    if (0 != dah_->GetDirKey(dir_.parent_path().string(), parent_key))
      return -1;
  } else {
#ifdef DEBUG
    printf("Keys needed because inside of Shares/Private.\n");
#endif
    std::string private_key("");
    if (0 != ss_->GetShareKeys(msid, parent_key, &private_key))
      return -1;
    *parent_key = SHA512(*parent_key, false);
  }
  return 0;
}

int SEHandler::EncryptDb(const std::string &dir_path,
                         const DirType dir_type,
                         const std::string &dir_key,
                         const std::string &msid,
                         const bool &encrypt_dm,
                         DataMap *dm) {
#ifdef DEBUG
  printf("SEHandler::EncryptDb dir_path(%s) type(%i) encrypted(%i) key(%s)\n",
         dir_path.c_str(), dir_type, encrypt_dm, HexSubstr(dir_key).c_str());
//  printf(" msid(%s)\n", msid.c_str());
#endif
  std::string ser_dm, enc_dm, db_path;
  SelfEncryption se(client_chunkstore_);
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path, CREATE, &db_path);
  if (!fs::exists(db_path))
    return -2;
  std::string file_hash = SHA512(db_path, true);

  // when encrypting root db and keys db (during logout), GetDbPath fails above,
  // so insert alternative value for file hashes.
  if (file_hash == "")
    file_hash = SHA512(db_path, false);
#ifdef DEBUG
  // printf("File hash = %s\n", file_hash);
#endif
  dm->set_file_hash(file_hash);
  if (se.Encrypt(db_path, false, dm) != 0) {
    return -1;
  }
  StoreChunks(*dm, dir_type, msid);
  dm->SerializeToString(&ser_dm);
  // if (ser_dm != "")
  //   ser_dm = ser_dm_;
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
  int result(kGeneralError);
  VoidFuncOneInt functor = boost::bind(&SEHandler::PacketOpCallback, this, _1,
                                       &mutex, &cond_var, &result);
  storem_->StorePacket(dir_key, enc_dm, PD_DIR, dir_type, msid, kOverwrite,
                       functor);
  while (result == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex);
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

int SEHandler::DecryptDb(const std::string &dir_path,
                         const DirType &dir_type,
                         const std::string &ser_dm,
                         const std::string &dir_key,
                         const std::string &msid,
                         bool dm_encrypted,
                         bool overwrite) {
#ifdef DEBUG
  printf("SEHandler::DecryptDb - dir_path(%s) type(%i) encrypted(%i) key(%s)",
         dir_path.c_str(), dir_type, dm_encrypted, HexSubstr(dir_key).c_str());
  printf(" msid(%s)\n", msid.c_str());
#endif
  std::string ser_dm_, enc_dm_;
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
    enc_dm_ = packet_content[0];
    std::map<std::string, std::string>::iterator it;
    it = uptodate_datamaps_.find(dir_path);

    if (it != uptodate_datamaps_.end()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Found dir_path in set.\n");
#endif
      if (dm_encrypted) {
        if (it->second == enc_dm_) {
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
      if (!gp.ParseFromString(enc_dm_)) {
#ifdef DEBUG
        printf("Failed to parse generic packet.\n");
#endif
        return -1;
      }
      enc_dm_ = gp.data();
      if (enc_dm_ == "") {
#ifdef DEBUG
        printf("Enc dm is empty.\n");
#endif
      }
    }
    if (dm_encrypted) {
#ifdef DEBUG
      printf("Decrypting dm.\n");
#endif
      int n = DecryptDm(dir_path, enc_dm_, msid, &ser_dm_);
#ifdef DEBUG
      printf("Decrypted dm.\n");
#endif
      if (n != 0 || ser_dm_ == "") {
#ifdef DEBUG
        printf("Died decrypting dm.\n");
#endif
        return -1;
      }

    } else {
      ser_dm_ = enc_dm_;
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
      enc_dm_ = gp.data();
      if (enc_dm_ == "") {
#ifdef DEBUG
        printf("Enc dm is empty.\n");
#endif
        return -1;
      }
    } else {
      enc_dm_ = ser_dm;
    }
    enc_dm_ = ser_dm;
    if (dm_encrypted) {
#ifdef DEBUG
      printf("Decrypting dm.\n");
#endif
      int n = DecryptDm(dir_path, enc_dm_, msid, &ser_dm_);
      if (n != 0 || ser_dm_ == "") {
#ifdef DEBUG
        printf("Died decrypting dm.\n");
#endif
        return -1;
      }
    } else {
      ser_dm_ = enc_dm_;
    }
  }

  DataMap dm;
  if (!dm.ParseFromString(ser_dm_)) {
#ifdef DEBUG
    printf("Doesn't parse as a dm.\n");
#endif
    return -1;
  }
  std::string db_path_;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler);
  dah_->GetDbPath(dir_path, CREATE, &db_path_);
//  CallbackResult cbr;
#ifdef DEBUG
  printf("Let's look for the chunks.\n");
#endif
  int n = LoadChunks(dm);
//  WaitForResult(cbr);
#ifdef DEBUG
  printf("Found the chunks: %d.\n", n);
#endif
//  GetResponse load_result;
//  load_result.Clear();
  if (n != 0) {
#ifdef DEBUG
    printf("Failed to get all chunks.\n");
#endif
    return -1;
  }
  SelfEncryption se(client_chunkstore_);
  if (se.Decrypt(dm, db_path_, 0, overwrite)) {
#ifdef DEBUG
    printf("Failed to self decrypt.\n");
#endif
    return -1;
  } else {
    if (dm_encrypted) {
      uptodate_datamaps_.insert(
        std::pair<std::string, std::string>(dir_path, enc_dm_));
    } else {
      uptodate_datamaps_.insert(
        std::pair<std::string, std::string>(dir_path, ser_dm));
    }
    return 0;
  }
}

int SEHandler::EncryptDm(const std::string &dir_path,
                         const std::string &ser_dm,
                         const std::string &msid,
                         std::string *enc_dm) {
  std::string key_, parent_key_, enc_hash_, xor_hash_, xor_hash_extended_="";
  // The following function sets parent_key_ to SHA512 hash of MSID public key
  // if msid != "" otherwise it sets it to the dir key of the parent folder
  GetDirKeys(dir_path, msid, &key_, &parent_key_);

  enc_hash_ = SHA512(parent_key_ + key_, false);
  xor_hash_ = SHA512(key_ + parent_key_, false);
#ifdef DEBUG
//  //  if (msid != "") {
//      printf("In EncryptDm dir_path: %s\n"
//             "key_: %s\nparent_key_: %s\nenc_hash_: %s\nxor_hash_: %s\n",
//              dir_path.c_str(), key_.c_str(),
//              parent_key_.c_str(), enc_hash_.c_str(), xor_hash_.c_str());
//  //  }
#endif
  while (xor_hash_extended_.size() < ser_dm.size())
    xor_hash_extended_.append(xor_hash_);
  xor_hash_extended_ = xor_hash_extended_.substr(0, ser_dm.size());
  crypto::Crypto encryptor_;
  encryptor_.set_symm_algorithm(crypto::AES_256);
  *enc_dm = encryptor_.SymmEncrypt((
      encryptor_.Obfuscate(ser_dm, xor_hash_extended_, crypto::XOR)),
      "",
      crypto::STRING_STRING,
      enc_hash_);
  return 0;
}

int SEHandler::DecryptDm(const std::string &dir_path,
                         const std::string &enc_dm,
                         const std::string &msid,
                         std::string *ser_dm) {
  std::string key_, parent_key_, enc_hash_, xor_hash_;
  std::string xor_hash_extended_="", intermediate_;
  // The following function sets parent_key_ to SHA512 hash of MSID public key
  // if msid != "" otherwise it sets it to the dir key of the parent folder
  int n = GetDirKeys(dir_path, msid, &key_, &parent_key_);
#ifdef DEBUG
//  printf("In DecryptDm dir_path: %s\tkey_: %s\tparent_key_: %s\n",
//          dir_path.c_str(), key_.c_str(), parent_key_.c_str());
#endif
  if (n != 0) {
#ifdef DEBUG
    printf("Error getting dir keys in SEHandler::DecryptDm.\n");
#endif
    return -1;
  }

  enc_hash_ = SHA512(parent_key_ + key_, false);
  xor_hash_ = SHA512(key_ + parent_key_, false);
#ifdef DEBUG
//  //  if (msid != "") {
//      printf("In DecryptDm dir_path: %s\n"
//             "key_: %s\nparent_key_: %s\nenc_hash_: %s\nxor_hash_: %s\n",
//              dir_path.c_str(), key_.c_str(),
//              parent_key_.c_str(), enc_hash_.c_str(), xor_hash_.c_str());
//  //  }
#endif
  crypto::Crypto decryptor_;
  decryptor_.set_symm_algorithm(crypto::AES_256);
  intermediate_ = decryptor_.SymmDecrypt(enc_dm,
                                         "",
                                         crypto::STRING_STRING,
                                         enc_hash_);
  while (xor_hash_extended_.size() < intermediate_.size())
    xor_hash_extended_.append(xor_hash_);
  xor_hash_extended_ = xor_hash_extended_.substr(0, intermediate_.size());

  *ser_dm = decryptor_.Obfuscate(intermediate_,
                                 xor_hash_extended_,
                                 crypto::XOR);
  if (*ser_dm == "") {
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
    printf("SEHandler::LoadChunks chunk(%s): result(%d)\n",
           HexSubstr(dm.encrypted_chunk_name(i)).c_str(), n);
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

void SEHandler::StoreChunks(const DataMap &dm,
                            const DirType dir_type,
                            const std::string &msid) {
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    storem_->StoreChunk(dm.encrypted_chunk_name(i), dir_type, msid);
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

}  // namespace maidsafe
