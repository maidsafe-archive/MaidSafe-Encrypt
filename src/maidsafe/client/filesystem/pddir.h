/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class for manipulating databases of directories
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


// Table mdm:-
// -----------
// id (int)  // This will save DB space in the DM table
// name (blob) (not NULL & unique): element name in lowercase
// display_name (blob): element name with appropriate capitalisations
// type (int): element type as per datamap.proto
// stats (varchar(1024)): Linux stats?
// tag (varchar(64)): media file tag?
// file_size_high (int): part of win filesize struct (set to NULL for Linux?)
// file_size_low (int): part of win filesize struct (set to filesize for Linux)
// creation_time (int): part of win file time struct (set to NULL for Linux?)
// last_modified (int): part of win file time struct (set to NULL for Linux?)
// last_access (int): part of win file time struct (set to NULL for Linux?)
// dir_key (varchar(64)): DHT key (the DHT value is encrypted dm of dir's db)
// primary key(id)
//
// Table dm:-
// ----------
// file_hash (varchar(64))
// id (int) constraint fk_id references mdm(id)
// ser_dm (varchar(5184)) - protocol buffer serialised datamap
// primary key(file_hash, id)


#ifndef MAIDSAFE_CLIENT_FILESYSTEM_PDDIR_H_
#define MAIDSAFE_CLIENT_FILESYSTEM_PDDIR_H_

#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>

#include <map>
#include <string>
#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/client/filesystem/distributed_filesystem.pb.h"

class CppSQLite3DB;

namespace fs = boost::filesystem;

namespace maidsafe {

namespace test { class DataAtlasHandlerTest_BEH_MAID_AddGetDataMapDetail_Test; }

class PdDir {
 public:
  PdDir() : db_(), db_name_(""), connected_(false) {}
  PdDir(const fs::path &db_name, DbInitFlag flag, int *result);
  ~PdDir();
  // retrieve dir_key so that db can be built
  int GetDirKey(const fs::path &file_name, std::string *dir_key);
  // returns the file's id in the db
  int GetIdFromName(const fs::path &file_name);
  // returns TRUE if the DM exists for the file
  bool DataMapExists(const int &id);
  // returns TRUE if the DM exists for the file
  bool DataMapExists(const std::string &file_hash);
  int AddElement(const std::string &ser_mdm,
                 const std::string &ser_dm,
                 const std::string &dir_key);
  // amend MDMs for files only
  int ModifyMetaDataMap(const std::string &ser_mdm, const std::string &ser_dm);
  int RemoveElement(const fs::path &file_name);
  int ListFolder(std::map<fs::path, ItemType> *children);
  int ListSubDirs(std::vector<fs::path> *subdirs_);
  int GetDataMapFromHash(const std::string &file_hash, std::string *ser_dm);
  int GetDataMap(const fs::path &file_name, std::string *ser_dm);
  int GetMetaDataMap(const fs::path &file_name, std::string *ser_mdm);
  int ChangeCtime(const fs::path &file_name);
  int ChangeMtime(const fs::path &file_name);
  int ChangeAtime(const fs::path &file_name);

 private:
  friend class test::DataAtlasHandlerTest_BEH_MAID_AddGetDataMapDetail_Test;
  int Init(DbInitFlag flag);
  // call one of connect, create, or build
  int Connect();
  // connect to existing db in folder
  int Create();
  // create default empty db when mkdir is called
  int Disconnect();
  // disconnect from current db.
  int ChangeTime(const fs::path &file_name, char time_type);
  void SanitiseSingleQuotes(std::string *str);
  boost::shared_ptr<CppSQLite3DB> db_;
  fs::path db_name_;
  bool connected_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_FILESYSTEM_PDDIR_H_

