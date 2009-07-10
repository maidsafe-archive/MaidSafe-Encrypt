/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages databases for directories
* Version:      1.0
* Created:      2009-01-28-11.23.16
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_DATAATLASHANDLER_H_
#define MAIDSAFE_CLIENT_DATAATLASHANDLER_H_

#include <list>
#include <map>
#include <string>
#include <vector>

#include "gtest/gtest_prod.h"

#include "maidsafe/client/keyatlas.h"
#include "maidsafe/client/pddir.h"

namespace maidsafe {

// These types are used by other components (i.e. authentication) also, other
// packet types are missing, these are only the signature packets.  Probably
// it would be useful to set this enumeration in another common header file.
enum CompareResults {EQUAL, UNEQUAL, COMPARE_ILLEGAL};

class DataAtlasHandler {
 private:
  FRIEND_TEST(DataAtlasHandlerTest, AddGetDataMapDAH);
  std::string db_dir_;
  // static DataAtlasHandler *single;
  boost::shared_ptr<PdDir> GetPdDir(const std::string &element_path,
                                    db_init_flag flag_,
                                    int *result);
  std::string GetElementNameFromPath(const std::string &element_path);
  // file_system::FileSystem *fsys_;
  std::map<std::string, PdDir*> dirs_;
  int CopyDb(const std::string &original_path_,
             const std::string &target_path_);
  int ListSubDirs(const std::string &element_path,
                  std::vector<std::string> *subdirs_);
  int CopySubDbs(const std::string &original_path_,
                 const std::string &target_path_);

  // methods for the Key Ring
  boost::shared_ptr<KeyAtlas> GetKeysDb(db_init_flag flag_, int *result);

 public:
  // static DataAtlasHandler *getInstance();
  DataAtlasHandler();
  ~DataAtlasHandler() {}  // delete single; }
  int Init(bool new_user_);

  // methods for normal folder Data Atlases
  void GetDbPath(const std::string &element_path,
                 db_init_flag flag_,
                 std::string *db_path);
  int AddElement(const std::string &element_path,
                 const std::string &ser_mdm,
                 const std::string &ser_dm,
                 const std::string &dir_key,
                 bool make_new_db);
  int ModifyMetaDataMap(const std::string &element_path,
                        const std::string &ser_mdm,
                        const std::string &ser_dm);
                        // amend MDMs for files only
  int RemoveElement(const std::string &element_path);
  int ListFolder(const std::string &element_path,
                 std::map<std::string, itemtype> *children);
  int RenameElement(const std::string &original_path,
                    const std::string &target_path,
                    bool force);
  int CopyElement(const std::string &original_path,
                  const std::string &target_path,
                  const std::string &new_dir_key,
                  bool force);
  int GetDirKey(const std::string &element_path, std::string *dir_key);
  int GetDataMap(const std::string &element_path, std::string *ser_dm);
  int GetMetaDataMap(const std::string &element_path, std::string *ser_mdm);
  int ChangeCtime(const std::string &element_path);
  int ChangeMtime(const std::string &element_path);
  int ChangeAtime(const std::string &element_path);
  int DisconnectPdDir(const std::string &branch_path);

  // methods for the Key Ring
//  void GetKeyDbPath(std::string *keys_db_name_);
//  int DisconnectKeysDb();
//  // int AddKeys(PacketType package_type, const std::string &package_id,
//  int AddKeys(const std::string &package_type,
//              const std::string &package_id,
//              const std::string &private_key,
//              const std::string &public_key);
//  std::string GetPackageID(const std::string &packet_type);
//  std::string GetPrivateKey(const std::string &packet_type);
//  std::string GetPublicKey(const std::string &packet_type);
//  int RemoveKeys(const std::string &package_type);
//  void GetKeyRing(std::list<Key_Type> *keyring);  // GetKeyRing List of structs
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_DATAATLASHANDLER_H_
