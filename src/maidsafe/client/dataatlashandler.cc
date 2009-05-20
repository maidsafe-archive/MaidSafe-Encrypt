/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages databases for directories
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

#include "maidsafe/client/dataatlashandler.h"

#include <stdint.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <exception>
#include <sstream>

#include "boost/filesystem.hpp"
#include "boost/shared_ptr.hpp"
// #include "boost/thread/mutex.hpp"

#include "maidsafe/utils.h"
#include "maidsafe/cppsqlite3.h"
#include "maidsafe/crypto.h"
#include "fs/filesystem.h"
#include "protobuf/datamaps.pb.h"
#include "maidsafe/maidsafe.h"

namespace fs = boost::filesystem;

namespace maidsafe {

DataAtlasHandler::DataAtlasHandler() :db_dir_(), dirs_() {
  file_system::FileSystem fsys_;
  if (maidsafe::SessionSingleton::getInstance()->SessionName() != "") {
    db_dir_ = fsys_.DbDir();
  } else {
    crypto::Crypto c;
    c.set_hash_algorithm("SHA1");
    std::string username = "user1";
    std::string pin = "1234";
    std::string s = c.Hash(pin+username, "", crypto::STRING_STRING, true);
    std::string mdir = ".maidsafe" + s;
    fs::path db_dir(fsys_.HomeDir());
    db_dir /= mdir;
    db_dir /= "dir";
    db_dir_ = db_dir.string();
  }
}


int DataAtlasHandler::Init(bool new_user_) {
  // set up keyring.db and home.db
  int result;
  if (!new_user_) {
    return 0;
  } else {
    // create root db
    boost::shared_ptr<PdDir> da_(GetPdDir("/", CREATE, &result));

    // create keys db
    std::string keys_db_name_;
    GetKeyDbPath(&keys_db_name_);
    int result_ = -1;
    boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CREATE, &result_));
    return 0;
  }
}

std::string DataAtlasHandler::GetElementNameFromPath(
    const std::string &element_path) {
#ifdef DEBUG
  // printf("\t\tGetElementNameFromPath::GetMetaDataMap %s\n",
  //   element_path.c_str());
#endif
  fs::path path_(element_path, fs::native);
  return path_.filename();
}

void DataAtlasHandler::GetDbPath(const std::string &element_path,
                                 db_init_flag flag_,
                                 std::string *db_path) {
  fs::path path_(element_path, fs::native);

  // unless we're creating a new dir db, the one we want is the branch of
  // element_path
  std::string pre_hash_db_name_;
  if (flag_ != CREATE) {
    // pre_hash_db_name_ = path_.parent_path().filename()+db_dir_;
    pre_hash_db_name_ = path_.parent_path().string() + db_dir_;
    // if the branch is null, we're making an element in the root, so set
    // pre_hash_db_name_ to "/"+db_dir_
    if (path_.parent_path().filename() == "")
      pre_hash_db_name_ = fs::path("/" + db_dir_, fs::native).string();
  } else {
    pre_hash_db_name_ = path_.string()+db_dir_;
  }

  crypto::Crypto crypto_;
  crypto_.set_hash_algorithm("SHA1");
  *db_path = crypto_.Hash(base::StrToLwr(pre_hash_db_name_),
                          "",
                          crypto::STRING_STRING,
                          true);

  fs::path db_path_(db_dir_, fs::native);
  db_path_ /= *db_path;
  *db_path = db_path_.string();
}


boost::shared_ptr<PdDir> DataAtlasHandler::GetPdDir(
    const std::string &element_path,
    db_init_flag flag_,
    int *result) {
  std::string db_name;
#ifdef DEBUG
  // printf("In getpddir: element_path = %s\tand flag_ = %i\n",
  //         element_path.c_str(),
  //         flag_);
#endif
  GetDbPath(element_path, flag_, &db_name);
#ifdef DEBUG
  // printf("In getpddir: getdbpath returned db_name as %s\n",
  //   db_name.c_str());
#endif
  int result_ = -1;
  boost::shared_ptr<PdDir> da_(new PdDir(db_name, flag_, &result_));
#ifdef DEBUG
  // printf("In getpddir: made new db with result %i\n", result_);
#endif
  *result = result_;
  return da_;
}


int DataAtlasHandler::AddElement(const std::string &element_path,
                                 const std::string &ser_mdm,
                                 const std::string &ser_dm,
                                 const std::string &dir_key,
                                 bool make_new_db) {
  int result;
  // create the new database if the element is a dir and make_new_db == true
  if (ser_dm == "" && make_new_db) {
#ifdef DEBUG
    // printf("This is a dir(%s)\n", element_path.c_str());
#endif
    boost::shared_ptr<PdDir> da_newdir_(GetPdDir(element_path,
                                                 CREATE, &result));
#ifdef DEBUG
    // printf("New dir's db added with result %i", result);
#endif
    if (result)
      return result;
  }

#ifdef DEBUG
  // printf("Getting db.\n");
#endif
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
#ifdef DEBUG
  // printf("Got db with result %i\n", result);
#endif
  if (result)
    return result;
#ifdef DEBUG
  // printf("Adding to db.\n");
#endif
  result = da_->AddElement(ser_mdm, ser_dm, dir_key);
#ifdef DEBUG
  // printf("Added to db with result %i\n", result);
#endif
  return result;
}


int DataAtlasHandler::ModifyMetaDataMap(const std::string &element_path,
                                        const std::string &ser_mdm,
                                        const std::string &ser_dm) {
  int result;
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  return da_->ModifyMetaDataMap(ser_mdm, ser_dm);
}


int DataAtlasHandler::RemoveElement(const std::string &element_path) {
  int result = 1;
  std::string ser_dm("");
  result = GetDataMap(element_path, &ser_dm);
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  result = da_->RemoveElement(GetElementNameFromPath(element_path));
  if (result != 0)
    return result;
  if (ser_dm == "") {
    try {
      std::string db_to_delete("");
      GetDbPath(element_path, CREATE, &db_to_delete);
      printf("Deleting DB: %s", db_to_delete.c_str());
      fs::remove(db_to_delete);
    }
    catch(const std::exception &e) {
      printf("%s", e.what());
      return -1;
    }
  }
  return 0;
}


int DataAtlasHandler::ListFolder(const std::string &element_path,
                                 std::map<std::string, itemtype> *children) {
  int result;
  if (element_path == "\\" || element_path == "/") {
    printf("It is indeed in here\n");
    children->insert(std::pair<std::string, itemtype>(
        base::TidyPath(kRootSubdir[0][0]), DIRECTORY));
    children->insert(std::pair<std::string, itemtype>(
        base::TidyPath(kRootSubdir[1][0]), DIRECTORY));
    return 0;
  }
  // append "/a" to element_path so that GetPdDir finds correct branch
  fs::path path_(element_path, fs::native);
  path_ /= "a";
  std::string element_path_modified = path_.string();
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path_modified,
                                        CONNECT, &result));
  if (result)
    return result;
  return da_->ListFolder(children);
}


int DataAtlasHandler::RenameElement(const std::string &original_path,
                                    const std::string &target_path,
                                    bool force) {
  // As this is a rename, where the element is a dir, the original dir key can
  // be used.
  std::string dir_key("");
  int n = GetDirKey(original_path, &dir_key);
  if (n != 0) {
#ifdef DEBUG
    printf("Could not get original_path dirkey.\n");
#endif
    return n;
  }
  if (CopyElement(original_path, target_path, dir_key, force)) {
#ifdef DEBUG
    printf("Element could not be copied.\n");
#endif
    return -1;
  }

  if (RemoveElement(original_path)) {
#ifdef DEBUG
    printf("Original element could not be removed.\n");
#endif
    return -1;
  }
  return 0;
}


int DataAtlasHandler::CopyElement(const std::string &original_path,
                                  const std::string &target_path,
                                  const std::string &new_dir_key_,
                                  bool force) {
  int result;
  boost::shared_ptr<PdDir> da_original_(GetPdDir(original_path,
                                                 CONNECT,
                                                 &result));
  if (result)
    return result;
  boost::shared_ptr<PdDir> da_target_(GetPdDir(target_path, CONNECT, &result));
  if (result)
    return result;
  std::string ser_mdm(""), ser_dm(""), original_name_, target_name_;
  original_name_ = GetElementNameFromPath(original_path);
  target_name_ = GetElementNameFromPath(target_path);

  // Check if target exists.  If so, and force==false, abort.
  result = da_target_->GetMetaDataMap(target_name_, &ser_mdm);
  if (!result) {  // i.e. target exists
    if (!force) {
#ifdef DEBUG
      printf("Target element already exists.\n");
#endif
      return -1;
    } else {
      // i.e. force==true, so delete old target in preparation of adding new.
      result = da_target_->RemoveElement(target_name_);
      if (result) {
#ifdef DEBUG
        printf("Couldn't remove existing target element before copying.\n");
#endif
        return -1;
      }
    }
  }

  // Get original mdm and dm
  ser_mdm = "";
  result = da_original_->GetMetaDataMap(original_name_, &ser_mdm);
  if (result) {
#ifdef DEBUG
    printf("Can't retrieve original mdm for copying.\n");
#endif
    return -1;
  }
  da_original_->GetDataMap(original_name_, &ser_dm);

  // Amend mdm
  MetaDataMap mdm;
  mdm.ParseFromString(ser_mdm);
  mdm.set_id(-2);
  mdm.set_display_name(target_name_);
  mdm.SerializeToString(&ser_mdm);

#ifdef DEBUG
  // Add these under target path
  // printf("In DAH::Cpyelmnt, addingelement: %s with sermdm %s & serdm %s\n",
  //        target_path.c_str(), ser_mdm.c_str(), ser_dm.c_str());
#endif
  result = AddElement(target_path, ser_mdm, ser_dm, new_dir_key_, false);
  if (result != 0) {
#ifdef DEBUG
    printf("In copyelement, result of addelement = %i\n", result);
#endif
    return result;
  }

  // If the element is a dir, the original db must be copied to the new one as
  // do any subdirs, sub-subdirs, etc.
  if (mdm.type() == 4 || mdm.type() == 5) {
    if (CopySubDbs(original_path, target_path)) {  // ie CopySubDbs failed
#ifdef DEBUG
      printf("In copyelement, result of addelement = %i\n", result);
#endif
      return -1;
    }
  }
  return 0;
}


int DataAtlasHandler::CopyDb(const std::string &original_path_,
                             const std::string &target_path_) {
  std::string original_db_path_, target_db_path_;
  GetDbPath(original_path_, CREATE, &original_db_path_);
  GetDbPath(target_path_, CREATE, &target_db_path_);
#ifdef DEBUG
  // printf("In DAH::CopyDb:\noriginal_db_path_ = %s\ntarget_db_path_ = %s\n\n",
  //        original_db_path_.c_str(), target_db_path_.c_str());
#endif
  if (fs::exists(target_db_path_))
    fs::remove(target_db_path_);
  fs::copy_file(original_db_path_, target_db_path_);
  return 0;
}


int DataAtlasHandler::ListSubDirs(const std::string &element_path,
                                  std::vector<std::string> *subdirs_) {
  int result;
  // append "/a" to element_path so that GetPdDir finds correct branch
  fs::path path_(element_path, fs::native);
  path_ /= "a";
  std::string element_path_modified = path_.string();

  boost::shared_ptr<PdDir> da_(GetPdDir(element_path_modified,
                                        CONNECT,
                                        &result));
  if (result)
    return result;
  return da_->ListSubDirs(subdirs_);
}


int DataAtlasHandler::CopySubDbs(const std::string &original_path_,
                                 const std::string &target_path_) {
#ifdef DEBUG
  // printf("In DAH::CopySubDbs:\noriginal_path_ = %s\ntarget_path_ = %s\n\n",
  //        original_path_.c_str(), target_path_.c_str());
#endif
  std::vector<std::string> subdirs_;
  if (ListSubDirs(original_path_, &subdirs_))  // ie ListSubDirs failed
    return -1;
  uint16_t i = 0;
  while (i < subdirs_.size()) {
    fs::path orig_path_(original_path_);
    fs::path targ_path_(target_path_);
    orig_path_ /= subdirs_[i];
    targ_path_ /= subdirs_[i];
    if (CopySubDbs(orig_path_.string(), targ_path_.string()))
      // ie CopySubDbs failed
      return -1;
    ++i;
  }
  if (CopyDb(original_path_, target_path_))  // ie CopyDb failed
    return -1;
  return 0;
}


int DataAtlasHandler::GetDirKey(const std::string &element_path,
                                std::string *dir_key) {
  int result;
#ifdef DEBUG
  printf("In DAH::GetDirKey, element_path_ = %s\n", element_path.c_str());
#endif
  if (element_path == "" || element_path == "/" || element_path == "\\") {
    *dir_key = maidsafe::SessionSingleton::getInstance()->RootDbKey();
    return 0;
  }
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result) {
#ifdef DEBUG
    printf("In DAH::GetDirKey, result from GetPdDir = %i\n", result);
#endif
    return result;
  }
  return da_->GetDirKey(GetElementNameFromPath(element_path), dir_key);
}


int DataAtlasHandler::GetDataMap(const std::string &element_path,
                                 std::string *ser_dm) {
  int result;
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  return da_->GetDataMap(GetElementNameFromPath(element_path), ser_dm);
}


int DataAtlasHandler::GetMetaDataMap(const std::string &element_path,
                                     std::string *ser_mdm) {
#ifdef DEBUG
  // printf("\t\tDataAtlasHandler::GetMetaDataMap %s\n", element_path.c_str());
#endif
  int result;
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  std::string the_path(GetElementNameFromPath(element_path));
#ifdef DEBUG
  // printf("\t\tDataAtlasHandler::GetMetaDataMap the_path: %s\n",
  //   the_path.c_str());
#endif
  result = da_->GetMetaDataMap(the_path, ser_mdm);
  return result;
}


int DataAtlasHandler::ChangeCtime(const std::string &element_path) {
  int result;
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  return da_->ChangeCtime(GetElementNameFromPath(element_path));
}


int DataAtlasHandler::ChangeMtime(const std::string &element_path) {
  int result;
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  return da_->ChangeMtime(GetElementNameFromPath(element_path));
}


int DataAtlasHandler::ChangeAtime(const std::string &element_path) {
  int result;
  boost::shared_ptr<PdDir> da_(GetPdDir(element_path, CONNECT, &result));
  if (result)
    return result;
  return da_->ChangeAtime(GetElementNameFromPath(element_path));
}


int DataAtlasHandler::DisconnectPdDir(const std::string &branch_path) {
  int result;
  // append "/a" to branch_path so that GetPdDir finds correct branch
  fs::path path_(branch_path, fs::native);
  path_ /= "a";
  std::string element_path_modified = path_.string();

  boost::shared_ptr<PdDir> da_(GetPdDir(element_path_modified,
                                        DISCONNECT,
                                        &result));
  if (result)
    return result;
  return 0;
}


// methods for the Key Ring
void DataAtlasHandler::GetKeyDbPath(std::string *keys_db_name_) {
  GetDbPath("/KeysDb", CREATE, keys_db_name_);
}


boost::shared_ptr<KeyAtlas> DataAtlasHandler::GetKeysDb(db_init_flag flag_,
                                                        int *result) {
  std::string keys_db_name_;
  GetDbPath("/KeysDb", CREATE, &keys_db_name_);
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(new KeyAtlas(keys_db_name_,
                                                   flag_,
                                                   &result_));
  *result = result_;
  return key_db_;
}


int DataAtlasHandler::DisconnectKeysDb() {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(DISCONNECT, &result_));
  return 0;
}


int DataAtlasHandler::AddKeys(const std::string &package_type, const
  std::string &package_id, const std::string &private_key, const std::string
  &public_key) {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CONNECT, &result_));
  return key_db_->AddKeys(package_type, package_id, private_key, public_key);
}


std::string DataAtlasHandler::GetPackageID(const std::string &packet_type) {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CONNECT, &result_));
  return key_db_->GetPackageID(packet_type);
}


std::string DataAtlasHandler::GetPrivateKey(const std::string &packet_type) {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CONNECT, &result_));
  return key_db_->GetPrivateKey(packet_type);
}


std::string DataAtlasHandler::GetPublicKey(const std::string &packet_type) {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CONNECT, &result_));
  return key_db_->GetPublicKey(packet_type);
}


int DataAtlasHandler::RemoveKeys(const std::string &package_type) {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CONNECT, &result_));
  return key_db_->RemoveKeys(package_type);
}


void DataAtlasHandler::GetKeyRing(std::list<Key_Type> *keyring) {
  int result_ = -1;
  boost::shared_ptr<KeyAtlas> key_db_(GetKeysDb(CONNECT, &result_));
  key_db_->GetKeyRing(keyring);
}

}  // namespace maidsafe
