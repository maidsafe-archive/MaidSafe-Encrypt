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
#include <cstdio>

#include "fs/filesystem.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/privateshares.h"
#include "protobuf/packet.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

SEHandler::SEHandler(StoreManagerInterface *storem,
                     boost::shared_ptr<ChunkStore> client_chunkstore,
                     boost::recursive_mutex *mutex)
                         : storem_(storem),
                           client_chunkstore_(client_chunkstore),
                           ss_(SessionSingleton::getInstance()),
                           mutex_(mutex),
                           fsys_(),
                           uptodate_datamaps_() {}

itemtype SEHandler::CheckEntry(const std::string &full_entry,
                               uint64_t *file_size) {
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
  SelfEncryption se_(client_chunkstore_);
  if (hash_contents) {
    fs::path path_(full_entry, fs::native);
    return se_.SHA512(path_);
  } else {
    return se_.SHA512(full_entry);
  }
}

int SEHandler::EncryptFile(const std::string &rel_entry,
                           const DirType dir_type,
                           const std::string &msid) {
  // boost::mutex::scoped_lock lock(mutex1_);
#ifdef DEBUG
  // printf("Encrypting: %s\n", rel_entry.c_str());
#endif
  // std::string rel_entry = fsys_->MakeRelativeMSPath(full_entry);
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler);
  std::string full_entry_ = fsys_.FullMSPathFromRelPath(rel_entry);

  uint64_t file_size_ = 0;
  itemtype type_ = CheckEntry(full_entry_, &file_size_);
  DataMap dm_, dm_retrieved_;
  std::string ser_dm_retrieved_="", ser_dm_="", ser_mdm_="";
  std::string file_hash_="", dir_key_="";
  SelfEncryption se_(client_chunkstore_);
#ifdef DEBUG
  // printf("Full entry: %s\n", full_entry_.c_str());
  // printf("Type: %i\n", type_);
  // printf("File size: %lu\n", file_size_);
#endif
  switch (type_) {
    // case DIRECTORY:
    // case EMPTY_DIRECTORY:
    //   GenerateUniqueKey(dir_key_);
    //   break;
    case EMPTY_FILE:
      dm_.set_file_hash(SHA512(full_entry_, true));
      dm_.SerializeToString(&ser_dm_);
      break;
    case REGULAR_FILE:
    case SMALL_FILE:
      file_hash_ = SHA512(full_entry_, true);
      // Try to get DM for this file.  If NULL return or file_hash
      // different, then encrypt.
      if (!dah_->GetDataMap(rel_entry, &ser_dm_retrieved_))  // ie found dm
        dm_retrieved_.ParseFromString(ser_dm_retrieved_);
      if (ser_dm_retrieved_ == "" || dm_retrieved_.file_hash() != file_hash_) {
        dm_.set_file_hash(file_hash_);
        if (se_.Encrypt(full_entry_, &dm_))
          return -2;
//          for(int i=0;i < dm_.encrypted_chunk_name_size();i++) {
//          //this needs threads or defereds threads is easier
//          //boost::mutex::scoped_lock lock(mutex_);
//          //Checking if node is in the network
//  //TODO(Richard): check if this op is going to work with callbacks(Kademlia)
//          if (storem_->IsKeyUnique(dm_.encrypted_chunk_name(i))) {
//            //TODO write the watchlist
//            std::string value;
//            //read the value of the chunk from the maidsafe dir
//         fs::path chunk_path = se_.GetChunkPath(dm_.encrypted_chunk_name(i));
//            uintmax_t size = fs::file_size(chunk_path);
//            boost::scoped_ptr<char> temp(new char[size]);
//            fs::ifstream fstr;
//            fstr.open(chunk_path, std::ios_base::binary);
//            fstr.read(temp.get(), size);
//            fstr.close();
//            std::string result((const char*)temp.get(), size);
//            value = result;
//
//            if (!(storem_->Store(dm_.encrypted_chunk_name(i), value, DATA)))
//              return -4;
//          }
// #ifdef DEBUG
//          else {
//            printf("Chunk already stored in the network\n");
//          }
// #endif
//        }

//        CallbackResult cbr;
//        StoreChunks(dm_,
//                    dir_type,
//                    msid,
//                    boost::bind(&CallbackResult::CallbackFunc, &cbr, _1));
//        WaitForResult(cbr);
        StoreChunks(dm_, dir_type, msid);
        dm_.SerializeToString(&ser_dm_);
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

  // boost::mutex::scoped_lock lock(mutex_);
  if (!ProcessMetaData(rel_entry, type_, file_hash_, file_size_, &ser_mdm_))
    return -11;
  if (dah_->AddElement(rel_entry, ser_mdm_, ser_dm_, dir_key_, true)) {
    // ie AddElements failed
    return -500;
  }
  // fs::remove(full_entry_);
  return 0;
  // size and stats missing TODO
  // add to stack filehash
  // some other thing saves session and pop x from stack
  // read stack to find whats stored
  // need a session update now
  // to ensure all is well before showing user files
  // are backed up completely
  // we should keep these and pass many at once to session
  // pass a finish flag to this.
  //    if (auth->SaveSession(da->SerialiseDataAtlas()) == OK)
  //    {
  //      for (int i=0;i < sizeof(vectorofnamesbackedup); i++)
  //        RETURN (!FSYS->WITEPATH(ENTRY,FSYS->DONE));
  //    }
}  // end EncryptFile

bool SEHandler::ProcessMetaData(const std::string &rel_entry,
                                const itemtype type,
                                const std::string &hash,
                                const uint64_t &file_size,
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
  // boost::mutex::scoped_lock lock(mutex3_);
#ifdef DEBUG
  // printf("Decrypting: %s\n", entry);
#endif
  DataMap dm;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler);
  std::string ser_dm_="";
  // std::string rel_entry = fsys_->MakeRelativeMSPath(full_entry_);
  std::string full_entry_ = fsys_.FullMSPathFromRelPath(rel_entry);
  // if we don't get DM, this is a directory and cannot be decrypted
  if (!dah_->GetDataMap(rel_entry, &ser_dm_)) {  // ie found dm
    std::string decrypted_path_ = fsys_.MakeMSPath(full_entry_);
    dm.ParseFromString(ser_dm_);
//    CallbackResult cbr;
    int n = LoadChunks(dm);
//    WaitForResult(cbr);
//    GetResponse result;
    if (n != 0) {
#ifdef DEBUG
      printf("Failed to get all chunks.\n");
#endif
      return -1;
    }
    SelfEncryption se(client_chunkstore_);
    if (se.Decrypt(dm, decrypted_path_, 0, false))
      return -1;
    else
      return 0;
  }
  return -2;
}

bool SEHandler::MakeElement(const std::string &rel_entry,
                            const itemtype type,
                            const DirType dir_type,
                            const std::string &msid,
                            const std::string &dir_key) {
  std::string ser_mdm_ = "", ser_dm_ = "", dir_key_(dir_key);
  if (!ProcessMetaData(rel_entry, type, "", 0, &ser_mdm_)) {
#ifdef DEBUG
    printf("Didn't process metadata.\n");
#endif
    return false;
  }
  if (type == EMPTY_DIRECTORY) {
    if (dir_key_ == "")
      GenerateUniqueKey(dir_type, msid, 0, &dir_key_);
  } else if (type == EMPTY_FILE) {
    DataMap dm_;
    dm_.set_file_hash(SHA512("", false));
    dm_.SerializeToString(&ser_dm_);
  } else {
#ifdef DEBUG
    printf("Type not recognised in SEHandler::MakeElement.\n");
#endif
    return false;
  }
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler);
  if (!dah_->AddElement(rel_entry, ser_mdm_, ser_dm_, dir_key_, true)) {
    // ie AddElement succeeded
    return true;
  } else {
#ifdef DEBUG
    printf("Didn't add element.\n");
#endif
    return false;
  }
}

int SEHandler::GenerateUniqueKey(const DirType dir_type,
                                 const std::string &msid,
                                 const int &attempt,
                                 std::string *hex_key) {
  // get key, check for uniqueness on DHT, and baggsy this key
  *hex_key = base::RandomString(200);
  *hex_key = SHA512(*hex_key, false);
  int count = attempt;
  while (!storem_->KeyUnique(*hex_key, false) && count < 5) {
    ++count;
    *hex_key = base::RandomString(200);
    *hex_key = SHA512(*hex_key, false);
  }
  if (count < 5) {
    ValueType pd_dir_type_;
    if (dir_type == ANONYMOUS)
      pd_dir_type_ = PDDIR_NOTSIGNED;
    else
      pd_dir_type_ = PDDIR_SIGNED;
    std::string ser_gp = CreateDataMapPacket("temp data", dir_type, msid);
    return storem_->StorePacket(*hex_key, "temp data", packethandler::PD_DIR,
                                dir_type, msid);
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
                         std::string *ser_dm) {
#ifdef DEBUG
  printf("SEHandler::EncryptDb dir_path(%s) type(%i) encrypted(%i) key(%s)\n",
         dir_path.c_str(), dir_type, encrypt_dm, dir_key.c_str());
//  printf(" msid(%s)\n", msid.c_str());
#endif
  DataMap dm_;
  std::string ser_dm_="", file_hash_="", enc_dm_;
  SelfEncryption se_(client_chunkstore_);
  std::string db_path_;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler);
  dah_->GetDbPath(dir_path, CREATE, &db_path_);
  if (!fs::exists(db_path_))
    return -2;
  file_hash_ = SHA512(db_path_, true);

  // when encrypting root db and keys db (during logout), GetDbPath fails above,
  // so insert alternative value for file hashes.
  if (file_hash_ == "")
    file_hash_ = SHA512(db_path_, false);
#ifdef DEBUG
  // printf("File hash = %s\n", file_hash_);
#endif
  dm_.set_file_hash(file_hash_);
  if (se_.Encrypt(db_path_, &dm_)) {
    return -1;
  }
//  CallbackResult cbr1;
//  StoreChunks(dm_,
//              dir_type,
//              msid,
//              boost::bind(&CallbackResult::CallbackFunc, &cbr1, _1));
//  WaitForResult(cbr1);
//  StoreResponse storechunks_result;
//  if ((!storechunks_result.ParseFromString(cbr1.result)) ||
//      (storechunks_result.result() == kNack)) {
//    return -1;
//  }
#ifdef DEBUG
  printf("SEHandler::EncryptDb - Fuck you Chavez!\n");
#endif
  StoreChunks(dm_, dir_type, msid);
#ifdef DEBUG
  printf("SEHandler::EncryptDb - After store chunks\n");
#endif
  dm_.SerializeToString(&ser_dm_);
  // if (ser_dm != "")
  //   ser_dm = ser_dm_;
  if (encrypt_dm) {
    EncryptDm(dir_path, ser_dm_, msid, &enc_dm_);
  } else {
    enc_dm_ = ser_dm_;
  }

  std::map<std::string, std::string>::iterator it;
  it = uptodate_datamaps_.find(dir_path);
  if (it != uptodate_datamaps_.end()) {
    if (it->second != enc_dm_) {
      uptodate_datamaps_.erase(it);
    }
  }
#ifdef DEBUG
//  std::string hex_dm("");
//  base::encode_to_hex(enc_dm_, &hex_dm);
//  printf("Inserting dir_path(%s) and enc_dm_(%s) into uptodate_datamaps_.\n",
//    dir_path.c_str(), hex_dm.c_str());
#endif
  uptodate_datamaps_.insert(
    std::pair<std::string, std::string>(dir_path, enc_dm_));


  // store encrypted dm to DHT
  // file_system::FileSystem fsys_;
  // fs::path temp_name_(fsys_.MaidsafeDir()+"/"+key);
  // std::ofstream out_;
  // out_.open(temp_name_.string().c_str(), std::ofstream::binary);
  // out_.write(enc_dm_.c_str(), enc_dm_.size());
  // out_.close();

  if (dir_key == "") {
#ifdef DEBUG
//    printf("dm is not stored in kademlia.\n");
#endif
    if (dir_type == ANONYMOUS) {
      *ser_dm = enc_dm_;
    } else {
      std::string ser_gp = CreateDataMapPacket(enc_dm_, dir_type, msid);
      *ser_dm = ser_gp;
#ifdef DEBUG
//      printf("Passing back ser_dm as a generic packet.\n");
#endif
    }
    return 0;
  }
  ValueType pd_dir_type_;
  if (dir_type == ANONYMOUS)
    pd_dir_type_ = PDDIR_NOTSIGNED;
  else
    pd_dir_type_ = PDDIR_SIGNED;
  std::string ser_gp = CreateDataMapPacket(enc_dm_, dir_type, msid);
  if (storem_->StorePacket(dir_key, ser_gp, packethandler::PD_DIR, dir_type,
      msid) == 0) {
#ifdef DEBUG
    printf("SEHandler::EncryptDb dir_path(%s) succeeded.\n", dir_path.c_str());
#endif
    return 0;
  } else {
#ifdef DEBUG
    printf("SEHandler::EncryptDb dir_path(%s) failed.\n", dir_path.c_str());
#endif
    return -1;
  }
}

int SEHandler::DecryptDb(const std::string &dir_path,
                         const DirType dir_type,
                         const std::string &ser_dm,
                         const std::string &dir_key,
                         const std::string &msid,
                         bool dm_encrypted,
                         bool overwrite) {
#ifdef DEBUG
  printf("SEHandler::DecryptDb dir_path(%s) type(%i) encrypted(%i) key(%s)",
         dir_path.c_str(), dir_type, dm_encrypted, dir_key.c_str());
  printf(" msid(%s)\n", msid.c_str());
#endif
  std::string ser_dm_, enc_dm_;
  // get dm from DHT
  if (ser_dm == "") {
    CallbackResult cbr;
    storem_->LoadPacket(dir_key,
                        boost::bind(&CallbackResult::CallbackFunc, &cbr, _1));
    WaitForResult(cbr);
    GetResponse load_result;
    if (!load_result.ParseFromString(cbr.result)) {
#ifdef DEBUG
      printf("Failed to load packet NO PARSE.\n");
#endif
      return -1;
    }
    if (load_result.result() != kAck) {
#ifdef DEBUG
      printf("Failed to load packet kNACK.\n");
#endif
      return -1;
    }
    if (!load_result.has_content()) {
#ifdef DEBUG
      printf("Failed to load packet NO CONTENT.\n");
#endif
      return -1;
    }

    packethandler::GenericPacket gp;
    gp.ParseFromString(load_result.content());
    enc_dm_ = gp.data();
    if (enc_dm_ == "") {
#ifdef DEBUG
      printf("Enc dm is empty.\n");
#endif
      return -1;
    }
#ifdef DEBUG
//    std::string hex_dm("");
//    base::encode_to_hex(enc_dm_, &hex_dm);
//    printf("Searching dir_path(%s) and enc_dm_(%s) in uptodate_datamaps_\n",
//      dir_path.c_str(), hex_dm.c_str());
#endif
    std::map<std::string, std::string>::iterator it;
    it = uptodate_datamaps_.find(dir_path);

    if (it != uptodate_datamaps_.end()) {
#ifdef DEBUG
      printf("SEHandler::DecryptDb: Found dir_path in set.\n");
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

//      if (dir_type != ANONYMOUS) {
//        packethandler::GenericPacket gp;
//        if (!gp.ParseFromString(enc_dm_)) {
//  #ifdef DEBUG
//          printf("Failed to parse generic packet.\n");
//  #endif
//          return -1;
//        }
//        enc_dm_ = gp.data();
//        if (enc_dm_ == "") {
//  #ifdef DEBUG
//          printf("Enc dm is empty.\n");
//  #endif
//        }
//      }
    if (dm_encrypted) {
#ifdef DEBUG
      printf("Decrypting dm.\n");
#endif
      int n = DecryptDm(dir_path, enc_dm_, msid, &ser_dm_);
#ifdef DEBUG
      printf("DecryptED dm.\n");
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
      packethandler::GenericPacket gp;
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
           dm.encrypted_chunk_name(i).substr(0, 8).c_str(), n);
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
//  base::pd_scoped_lock gaurd(*mutex_);
//  DirType dir_type = PRIVATE;
//  std::string msid("");
//  boost::shared_ptr<ChunksData> data(new ChunksData(dm, dir_type, msid, cb));
//  IterativeLoadChunks(data);
}

void SEHandler::IterativeLoadChunks(
    boost::shared_ptr<ChunksData> data) {
  if (data->is_calledback) {
    return;
  }
  GetResponse local_result;
  std::string str_local_result;
  if (data->chunks_done == data->total_chunks) {
    local_result.set_result(kAck);
    data->is_calledback = true;
    local_result.SerializeToString(&str_local_result);
    data->cb(str_local_result);
    return;
  }
  if ((data->index >= data->total_chunks) &&
      (data->active_chunks == 0)) {
    local_result.set_result(kNack);
    data->is_calledback = true;
    local_result.SerializeToString(&str_local_result);
    data->cb(str_local_result);
    return;
  }
  if (data->index < data->total_chunks &&
      data->active_chunks < kParallelLoads) {
    int chunks_to_store = kParallelLoads - data->active_chunks;
    for (int i = 0;
         i < chunks_to_store && data->index < data->total_chunks-1;
         ++i) {
      ++data->index;
      ++data->active_chunks;
      LoadChunk(data->dm.encrypted_chunk_name(data->index), 0, data);
    }
  }
}

void SEHandler::LoadChunk(const std::string &chunk_name,
                          int retry,
                          boost::shared_ptr<ChunksData> data) {
  if (data->is_calledback) {
    return;
  }
  if (retry < kMaxLoadRetries) {
    ++data->chunks_done;
    --data->active_chunks;
    SelfEncryption se_(client_chunkstore_);
    fs::path chunk_path = se_.GetChunkPath(chunk_name);
    if (!fs::exists(chunk_path)) {
      std::string content;
      storem_->LoadChunk(chunk_name, &content);
      fs::ofstream ofs;
      ofs.open(chunk_path, std::ios_base::binary);
      ofs.write(content.c_str(), content.size());
      ofs.close();
      IterativeLoadChunks(data);
    } else {
      --data->active_chunks;
      ++data->chunks_done;
      IterativeLoadChunks(data);
      return;
    }
  } else {
    GetResponse local_result;
    std::string str_local_result;
    local_result.set_result(kNack);
    data->is_calledback = true;
    local_result.SerializeToString(&str_local_result);
    data->cb(str_local_result);
  }
}

void SEHandler::StoreChunks(const DataMap &dm,
                            const DirType dir_type,
                            const std::string &msid) {
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    storem_->StoreChunk(dm.encrypted_chunk_name(i), dir_type, msid);
}

void SEHandler::WaitForResult(const CallbackResult &cb) {
  while (true) {
    {
      base::pd_scoped_lock gaurd(*mutex_);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
}

std::string SEHandler::CreateDataMapPacket(const std::string &ser_dm,
                                           const DirType dir_type,
                                           const std::string &msid) {
  if (dir_type == ANONYMOUS)
    return ser_dm;
  packethandler::GenericPacket gp;
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  gp.set_data(ser_dm);
  std::string private_key("");
  switch (dir_type) {
    case PRIVATE_SHARE: {
        std::string public_key("");
        if (0 != ss_->GetShareKeys(msid, &public_key, &private_key)) {
          private_key = "";
          return "";
        }
      }
      break;
    case PUBLIC_SHARE:
      private_key = ss_->PrivateKey(MPID);
      break;
    default:
      private_key = ss_->PrivateKey(PMID);
      break;
  }
  gp.set_signature(co.AsymSign(gp.data(),
                               "",
                               private_key,
                               crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  return ser_gp;
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


CallbackResult::CallbackResult() : result("") {}

void CallbackResult::CallbackFunc(const std::string &res) {
  result = res;
}

void CallbackResult::Reset() {
  result = "";
}

}  // namespace maidsafe
