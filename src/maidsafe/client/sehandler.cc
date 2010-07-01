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

#include "maidsafe/pdutils.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

void SEHandler::Init(boost::shared_ptr<StoreManagerInterface> storem,
                     boost::shared_ptr<ChunkStore> client_chunkstore) {
  storem_ = storem;
  client_chunkstore_ = client_chunkstore;
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  up_to_date_datamaps_.clear();
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
#ifdef DEBUG
  // printf("Encrypting: %s\n", rel_entry.c_str());
#endif
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string full_entry = file_system::FullMSPathFromRelPath(
      rel_entry, ss_->SessionName()).string();

  boost::uint64_t file_size = 0;
  std::string file_hash;
  ItemType item_type = CheckEntry(full_entry, &file_size, &file_hash);
  DataMap dm, dm_retrieved;
  std::string ser_dm_retrieved, ser_dm, ser_mdm, dir_key;
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
          return kEncryptFileFailure;
        StoreChunks(dm, dir_type, msid);
        dm.SerializeToString(&ser_dm);
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

  if (!ProcessMetaData(rel_entry, item_type, file_hash, file_size, &ser_mdm))
    return kEncryptionMDMFailure;
  if (dah->AddElement(rel_entry, ser_mdm, ser_dm, dir_key, true) != kSuccess) {
    return kEncryptionDAHFailure;
  }
  return kSuccess;
}

int SEHandler::EncryptString(const std::string &data,
                             std::string *ser_dm) {
  if (data.empty())
    return kEncryptionSmallInput;
  maidsafe::DataMap dm;
  SelfEncryption se(client_chunkstore_);
  ser_dm->clear();
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  dm.set_file_hash(co.Hash(data, "", crypto::STRING_STRING, false));
  if (se.Encrypt(data, true, &dm))
    return kEncryptStringFailure;
#ifdef DEBUG
//  printf("SEHandler::EncryptString - Total chunks: %d\n",
//         dm.encrypted_chunk_name_size());
//  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i) {
//    printf("SEHandler::LoadChunks %d of %d, chunk(%s)\n",
//           i + 1, dm.encrypted_chunk_name_size(),
//           HexSubstr(dm.encrypted_chunk_name(i)).c_str());
//  }
#endif
  StoreChunks(dm, PRIVATE, "");
  if (!dm.SerializeToString(ser_dm)) {
#ifdef DEBUG
    printf("SEHandler::EncryptString - Failed to serialize dm\n");
#endif
    return kEncryptionDMFailure;
  }
  return kSuccess;
}

bool SEHandler::ProcessMetaData(const std::string &rel_entry,
                                const ItemType &type,
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
    if (n != kSuccess) {
#ifdef DEBUG
      printf("Failed to get all chunks.\n");
#endif
      return kEncryptionSMFailure;
    }
    SelfEncryption se(client_chunkstore_);
    if (se.Decrypt(dm, decrypted_path, 0, false) == kSuccess)
      return kSuccess;
    else
      return kDecryptFileFailure;
  }
  return kEncryptionDAHFailure;
}

int SEHandler::DecryptString(const std::string &ser_dm,
                             std::string *dec_string) {
  DataMap dm;
  dec_string->clear();
  if (!dm.ParseFromString(ser_dm)) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to parse into DM.\n");
#endif
    return kEncryptionDMFailure;
  }
  if (LoadChunks(dm) != kSuccess) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to get all chunks.\n");
#endif
    return kEncryptionSMFailure;
  }
  SelfEncryption se(client_chunkstore_);
  if (se.Decrypt(dm, 0, dec_string) != kSuccess) {
#ifdef DEBUG
      printf("SEHandler::DecryptString - Failed to decrypt.\n");
#endif
    return kDecryptStringFailure;
  }
  return kSuccess;
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
  if (dah->AddElement(rel_entry, ser_mdm, ser_dm, dir_key, true) == kSuccess) {
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
  return (count < 5) ? kSuccess : kEncryptionKeyGenFailure;
}

int SEHandler::GetDirKeys(const std::string &dir_path,
                          const std::string &msid,
                          std::string *key,
                          std::string *parent_key) {
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  std::string tidy_path = TidyPath(dir_path);
  fs::path dir(tidy_path, fs::native);
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
    if (kSuccess != ss_->GetShareKeys(msid, parent_key, &private_key))
      return kEncryptionGetDirKeyFailure;
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    *parent_key = co.Hash(*parent_key, "", crypto::STRING_STRING, false);
  }
  return kSuccess;
}

int SEHandler::EncryptDb(const std::string &dir_path,
                         const DirType &dir_type,
                         const std::string &dir_key,
                         const std::string &msid,
                         const bool &encrypt_dm,
                         DataMap *dm) {
#ifdef DEBUG
//  printf("SEHandler::EncryptDb dir_path(%s) type(%i) encrypted(%i) key(%s)\n",
//         dir_path.c_str(), dir_type, encrypt_dm, HexSubstr(dir_key).c_str());
//  printf(" msid(%s)\n", msid.c_str());
#endif

  std::string ser_dm, enc_dm, db_path;
  SelfEncryption se(client_chunkstore_);
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path, CREATE, &db_path);
  try {
    if (!fs::exists(db_path))
      return kEncryptionDbMissing;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SEHandler::EncryptDb - Can't check DB path\n");
#endif
    return kEncryptionDbException;
  }
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string file_hash = co.Hash(db_path, "", crypto::FILE_STRING, false);

  // when encrypting root db and keys db (during logout), GetDbPath fails above,
  // so insert alternative value for file hashes.
  if (file_hash.empty())
    file_hash = co.Hash(db_path, "", crypto::STRING_STRING, false);
  dm->set_file_hash(file_hash);
  if (se.Encrypt(db_path, false, dm) != kSuccess) {
    return kEncryptDbFailure;
  }
  dm->SerializeToString(&ser_dm);
  if (encrypt_dm)
    EncryptDm(dir_path, ser_dm, msid, &enc_dm);
  else
    enc_dm = ser_dm;

  std::string previous_enc_dm = AddToUpToDateDms(dir_key, enc_dm);
  if (previous_enc_dm == enc_dm)
    return kSuccess;

  StoreChunks(*dm, dir_type, msid);
  if (dir_key.empty()) {  // Means we're not storing to DHT - used by client
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
  if (previous_enc_dm.empty()) {
    storem_->StorePacket(dir_key, enc_dm, PD_DIR, dir_type, msid, functor);
  } else {
    storem_->UpdatePacket(dir_key, previous_enc_dm, enc_dm, PD_DIR, dir_type,
                          msid, functor);
  }
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kPendingResult)
      cond_var.wait(lock);
  }
  return (result == kSuccess) ? kSuccess : kEncryptDbFailure;
}

int SEHandler::DecryptDb(const std::string &dir_path,
                         const DirType &dir_type,
                         const std::string &encrypted_dm,
                         const std::string &dir_key,
                         const std::string &msid,
                         bool dm_encrypted,
                         bool overwrite) {
#ifdef DEBUG
//  printf("SEHandler::DecryptDb - dir_path(%s) type(%i) encrypted(%i) key(%s)",
//         dir_path.c_str(), dir_type, dm_encrypted,
//         HexSubstr(dir_key).c_str());
//  printf(" msid(%s)\n", msid.c_str());
#endif

  std::string enc_dm;
  // get dm from up_to_date_ map or DHT
  if (encrypted_dm.empty()) {
    std::string current_enc_dm = GetFromUpToDateDms(dir_key);
    if (!GetFromUpToDateDms(dir_key).empty()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Found dir_key; db is up to date.\n");
#endif
      return kSuccess;
    }
    std::vector<std::string> packet_content;
    int result = storem_->LoadPacket(dir_key, &packet_content);
    if (result != kSuccess || packet_content.empty() ||
        packet_content[0].empty()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb - Enc dm is empty.\n");
#endif
      return kDecryptDbFailure;
    }
    std::string enc_dm_ser_generic_packet = packet_content[0];
    if (dir_type != ANONYMOUS) {
      GenericPacket gp;
      if (!gp.ParseFromString(enc_dm_ser_generic_packet)) {
#ifdef DEBUG
        printf("Failed to parse generic packet.\n");
#endif
        return kDecryptDbFailure;
      }
      enc_dm = gp.data();
      // TODO(Fraser#5#): 2010-06-28 - Check gp signature is valid
      if (enc_dm.empty()) {
#ifdef DEBUG
        printf("Enc dm is empty.\n");
#endif
        return kDecryptDbFailure;
      }
    }
  } else {
    enc_dm = encrypted_dm;
  }

  std::string ser_dm = enc_dm;
  if (dm_encrypted) {
    int n = DecryptDm(dir_path, enc_dm, msid, &ser_dm);
    if (n != kSuccess || ser_dm.empty()) {
#ifdef DEBUG
      printf("Died decrypting dm.\n");
#endif
      return kDecryptDbFailure;
    }
  }

  DataMap dm;
  if (!dm.ParseFromString(ser_dm)) {
#ifdef DEBUG
    printf("Doesn't parse as a dm.\n");
#endif
    return kDecryptDbFailure;
  }

  std::string db_path;
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  dah->GetDbPath(dir_path, CREATE, &db_path);

  int result = LoadChunks(dm);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Failed to get all chunks.\n");
#endif
    return kDecryptDbFailure;
  }

  SelfEncryption se(client_chunkstore_);
  if (se.Decrypt(dm, db_path, 0, overwrite)) {
#ifdef DEBUG
    printf("Failed to self decrypt.\n");
#endif
    return kDecryptDbFailure;
  } else {
    if (dm_encrypted) {
      AddToUpToDateDms(dir_key, enc_dm);
    } else {
      AddToUpToDateDms(dir_key, ser_dm);
    }
    return kSuccess;
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

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  enc_hash_ = co.Hash(parent_key_ + key_, "", crypto::STRING_STRING, false);
  xor_hash_ = co.Hash(key_ + parent_key_, "", crypto::STRING_STRING, false);
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
  return kSuccess;
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
  if (n != kSuccess) {
#ifdef DEBUG
    printf("Error getting dir keys in SEHandler::DecryptDm.\n");
#endif
    return kDecryptDbFailure;
  }

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  enc_hash_ = co.Hash(parent_key_ + key_, "", crypto::STRING_STRING, false);
  xor_hash_ = co.Hash(key_ + parent_key_, "", crypto::STRING_STRING, false);
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
  if (ser_dm->empty()) {
#ifdef DEBUG
    printf("Error decrypting in SEHandler::DecryptDm.\n");
#endif
    return kDecryptDbFailure;
  }
  return kSuccess;
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

void SEHandler::StoreChunks(const DataMap &dm,
                            const DirType &dir_type,
                            const std::string &msid) {
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    storem_->StoreChunk(dm.encrypted_chunk_name(i), dir_type, msid);
}

std::string SEHandler::AddToUpToDateDms(const std::string &dir_key,
                                        const std::string &enc_dm) {
  std::string previous_enc_dm;
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  // returns insertion position if dir_key doesn't already exist in map
  UpToDateDatamaps::iterator lb = up_to_date_datamaps_.lower_bound(dir_key);
  if (lb != up_to_date_datamaps_.end() &&
      !(up_to_date_datamaps_.key_comp()(dir_key, lb->first))) {
    // dir_key already exists
    previous_enc_dm = lb->second;
    if (previous_enc_dm != enc_dm)
      lb->second = enc_dm;
  } else {
    // dir_key doesn't exist
    up_to_date_datamaps_.insert(lb,
                                UpToDateDatamaps::value_type(dir_key, enc_dm));
  }
  return previous_enc_dm;
}

std::string SEHandler::GetFromUpToDateDms(const std::string &dir_key) {
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  UpToDateDatamaps::iterator it = up_to_date_datamaps_.find(dir_key);
  return (it == up_to_date_datamaps_.end()) ? "" : (*it).second;
}

int SEHandler::RemoveFromUpToDateDms(const std::string &dir_key) {
  boost::mutex::scoped_lock lock(up_to_date_datamaps_mutex_);
  size_t removed_count = up_to_date_datamaps_.erase(dir_key);
  return removed_count ? kSuccess : kEncryptionDmNotInMap;
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
