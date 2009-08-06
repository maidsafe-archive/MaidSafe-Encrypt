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


#ifndef MAIDSAFE_CLIENT_PDDIR_H_
#define MAIDSAFE_CLIENT_PDDIR_H_

#include <boost/shared_ptr.hpp>
#include <gtest/gtest_prod.h>

#include <map>
#include <string>
#include <vector>

#include "maidsafe/cppsqlite3.h"
#include "maidsafe/maidsafe.h"

namespace maidsafe {

class PdDir {
 public:
  PdDir() : db_name_(""), db_() {}
  PdDir(const std::string &db_name, DbInitFlag flag_, int *result_);
  ~PdDir();
  int GetDirKey(const std::string &file_name, std::string *dir_key);
  // retrieve dir_key so that db can be built
  int GetIdFromName(const std::string &file_name);
  // returns the file's id in the db
  bool DataMapExists(const int &id);
  // returns TRUE if the DM exists for the file
  bool DataMapExists(const std::string &file_hash);
  // returns TRUE if the DM exists for the file
  int AddElement(const std::string &ser_mdm,
                 const std::string &ser_dm,
                 const std::string &dir_key="");
  int ModifyMetaDataMap(const std::string &ser_mdm, const std::string &ser_dm);
  // amend MDMs for files only
  int RemoveElement(const std::string &file_name);
  int ListFolder(std::map<std::string, itemtype> *children);
  int ListSubDirs(std::vector<std::string> *subdirs_);
  int GetDataMapFromHash(const std::string &file_hash, std::string *ser_dm);
  int GetDataMap(const std::string &file_name, std::string *ser_dm);
  int GetMetaDataMap(const std::string &file_name, std::string *ser_mdm);
  int ChangeCtime(const std::string &file_name);
  int ChangeMtime(const std::string &file_name);
  int ChangeAtime(const std::string &file_name);

 private:
  std::string db_name_;
  boost::shared_ptr<CppSQLite3DB> db_;
  // CppSQLite3DB *db_;
  int Init(DbInitFlag flag_);
  // call one of connect, create, or build
  FRIEND_TEST(DataAtlasHandlerTest, BEH_MAID_AddGetDataMapDA);
  int Connect();
  // connect to existing db in folder
  int Create();
  // create default empty db when mkdir is called
  int Disconnect();
  // disconnect from current db.
  int ChangeTime(const std::string &file_name, char time_type);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_PDDIR_H_

