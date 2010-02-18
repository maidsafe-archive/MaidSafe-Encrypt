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

#include "maidsafe/client/pddir.h"

#include <boost/filesystem.hpp>

#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/crypto.h>
#include <maidsafe/utils.h>

#include <stdint.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <exception>
#include <list>
#include <map>
#include <string>
#include <vector>


#include "protobuf/datamaps.pb.h"
#include "maidsafe/maidsafe.h"

namespace fs = boost::filesystem;

void SanitiseSingleQuotes(std::string *str) {
  for (unsigned int i = 0; i < str->length(); ++i) {
    if (str->at(i) == '\'') {
      str->insert(i, "'");
      ++i;
    }
  }
}

namespace maidsafe {

PdDir::PdDir(const std::string &db_name, DbInitFlag flag, int *result)
    : db_name_(), db_(), connected_(false) {
  boost::shared_ptr<CppSQLite3DB> db(new CppSQLite3DB());
  db_ = db;
  db_name_.assign(db_name);
  *result = Init(flag);
}

PdDir::~PdDir() {
  Disconnect();
}

int PdDir::Init(DbInitFlag flag) {
  switch (flag) {
    case CONNECT:
#ifdef DEBUG
      // printf("In PdDir Init:CONNECT\n");
#endif
      return Connect();
    case CREATE:
      return Create();
    case DISCONNECT:
      return Disconnect();
    default:
      return kDataAtlasError;
  }
}

int PdDir::Connect() {
  if (connected_)
    return kSuccess;
  if (!fs::exists(db_name_)) {
#ifdef DEBUG
    printf("In PdDir Connect: No DB\n");
#endif
    return kDBDoesntExist;
  }
  try {
#ifdef DEBUG
    // printf("In PdDir Connect: Before open\n");
#endif
    db_->open(db_name_.c_str());
#ifdef DEBUG
    // printf("In PdDir Connect: After open\n");
#endif
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBOpenException;
  }
  connected_ = true;
  return kSuccess;
}

int PdDir::Create() {
  if (connected_)
    return kSuccess;
  // if (fs::exists(db_name_))
    // return -3;
  try {
    db_->open(db_name_.c_str());
    // create table structure
    db_->execDML("drop table if exists mdm");
    db_->execDML("drop table if exists dm");
    // db_->execDML("create table mdm(id int, name blob not null unique,
    //   display_name blob, type int, stats varchar(1024), tag varchar(64),
    //   file_size_high blob null, file_size_low blob null,
    //   creation_time blob null, last_modified blob null,
    //   last_access blob null, dir_key varchar(64), primary key(id));");
    std::string s1 = "create table mdm(id int, name blob not null unique,";
    s1 += "display_name blob, type int, stats varchar(1024), tag varchar(64),";
    s1 += "file_size_high int null, file_size_low int null, ";
    s1 += "creation_time int null, last_modified int null, ";
    s1 += "last_access int null, dir_key varchar(64), primary key(id));";
    db_->execDML(s1.c_str());
    std::string s2 = "create table dm(file_hash varchar(64), ";
    s2 += "id int not null constraint fk_id references mdm(id), ";
    s2 += "ser_dm varchar(5184), primary key(file_hash, id));";
    db_->execDML(s2.c_str());
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBCreateException;
  }
  connected_ = true;
  return kSuccess;
}

int PdDir::GetDirKey(const std::string &file_name, std::string *dir_key) {
  *dir_key = "";
  int id = GetIdFromName(file_name);
  if (id < 0)
    return id;
  try {
    std::string s = "select dir_key from mdm where id=" + base::itos(id) + ";";
#ifdef DEBUG
    // printf("%s\n", s.c_str());
#endif
    CppSQLite3Query q_mdm = db_->execQuery(s.c_str());
    if (q_mdm.eof()) {
#ifdef DEBUG
      printf("PdDir::GetDirKey key not found.\n");
#endif
      return kDBCantFindDirKey;
    } else {
      *dir_key = base::DecodeFromHex(
                 q_mdm.fieldValue(static_cast<unsigned int>(0)));
      return kSuccess;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::Disconnect() {
  if (!connected_)
    return kSuccess;
  try {
    if (!fs::exists(db_name_))
      return kDBDoesntExist;
    db_->close();
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBCloseException;
  }
  connected_ = false;
  return kSuccess;
}

int PdDir::GetIdFromName(const std::string &file_name) {
  std::string name = base::StrToLwr(file_name);
  SanitiseSingleQuotes(&name);
  std::string s = "select id from mdm where name='" + name + "';";
  try {
    CppSQLite3Query q_mdm = db_->execQuery(s.c_str());
    if (!q_mdm.eof()) {
      return q_mdm.getIntField(0);
    } else {  // mdm name is not there
      return kDBCantFindFile;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

bool PdDir::DataMapExists(const int &id) {
  try {
    std::string s = "select * from dm where id=" + base::itos(id) + ";";
    CppSQLite3Query q_dm = db_->execQuery(s.c_str());
    return !q_dm.eof();
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return false;
  }
}

bool PdDir::DataMapExists(const std::string &file_hash) {
  try {
    std::string s = "select * from dm where file_hash='" +
                    base::EncodeToHex(file_hash) + "';";
    CppSQLite3Query q_dm = db_->execQuery(s.c_str());
    return !q_dm.eof();
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return false;
  }
}

int PdDir::AddElement(const std::string &ser_mdm,
                      const std::string &ser_dm,
                      const std::string &dir_key) {
  // use ModifyMetaDataMap for files (not dirs) which already exist in db
  if (ModifyMetaDataMap(ser_mdm, ser_dm) == kSuccess)
    return kSuccess;

  MetaDataMap mdm;
  DataMap dm;
  try {
    if (!mdm.ParseFromString(ser_mdm))
      return kParseDataMapError;
    if (ser_dm != "")
      if (!dm.ParseFromString(ser_dm))
        return kParseDataMapError;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kParseDataMapError;
  }
  try {
    bool mdm_exists = true;
    // search for the mdm in the db
    int id = GetIdFromName(mdm.display_name());
    if (id < 0) {
#ifdef DEBUG
      // printf("Didn't find the mdm.\n");
#endif
      if (mdm.id() == -2) {
        mdm_exists = false;
        std::string sel_max = "select max(id) from mdm;";
        CppSQLite3Query get_max_id_query = db_->execQuery(sel_max.c_str());
        mdm.set_id(get_max_id_query.getIntField(0) + 1);
        get_max_id_query.finalize();
      } else {
        return kAddElementError;
      }
    } else {
      mdm.set_id(id);
    }

    int ins_mdm = 0, ins_dm = 0;
    std::string name = base::StrToLwr(mdm.display_name());
    if (!mdm_exists) {  // mdm name is not there
      // add to mdm
      CppSQLite3Statement stmt = db_->compileStatement(
          "insert into mdm values(?,?,?,?,?,?,?,?,?,?,?,?);");
      stmt.bind(1, mdm.id());
      stmt.bind(2, name.c_str());
      stmt.bind(3, mdm.display_name().c_str());
      stmt.bind(4, mdm.type());
      stmt.bind(5, mdm.stats().c_str());
      stmt.bind(6, mdm.tag().c_str());
      // stmt.bind(7, base::itos_ull(mdm.file_size_high()).c_str());
      // stmt.bind(8, base::itos_ull(mdm.file_size_low()).c_str());
      // stmt.bind(9, base::itos_ull(mdm.creation_time()).c_str());
      stmt.bind(7, mdm.file_size_high());
      stmt.bind(8, mdm.file_size_low());
      stmt.bind(9, mdm.creation_time());
      boost::uint32_t current_time = base::get_epoch_time();
      // stmt.bind(10, base::itos_ul(current_time).c_str());
      // stmt.bind(11, base::itos_ul(current_time).c_str());
      stmt.bind(10, base::itos_ul(current_time).c_str());
      stmt.bind(11, base::itos_ul(current_time).c_str());
      stmt.bind(12, base::EncodeToHex(dir_key).c_str());
      ins_mdm = stmt.execDML();
      stmt.finalize();

      if (ser_dm != "") {
        CppSQLite3Statement stmt1 = db_->compileStatement(
            "insert into dm values(?,?,?);");
        stmt1.bind(1, base::EncodeToHex(dm.file_hash()).c_str());
        stmt1.bind(2, mdm.id());
        stmt1.bind(3, base::EncodeToHex(ser_dm).c_str());
        // printf("aaaaaaaaaaaa %s\n", ser_dm.c_str());
        ins_dm = stmt1.execDML();
        stmt1.finalize();
      } else {
        ins_dm = 1;
      }
    } else {  // mdm name is already there
      if (ser_dm == "") {
        // if this is a dir, not a file (files should have been handled by
        // ModifyMetaDataMap)
        std::string s = "update mdm set type = ?, stats = ?, tag = ?, ";
        s += "last_modified = ?, last_access = ? where id = ?;";
        CppSQLite3Statement stmt2 = db_->compileStatement(s.c_str());
        stmt2.bind(1, mdm.type());
        stmt2.bind(2, mdm.stats().c_str());
        stmt2.bind(3, mdm.tag().c_str());
        boost::uint32_t current_time = base::get_epoch_time();
        // stmt2.bind(4, base::itos_ul(current_time).c_str());
        // stmt2.bind(5, base::itos_ul(current_time).c_str());
        stmt2.bind(4, static_cast<int>(current_time));
        stmt2.bind(5, static_cast<int>(current_time));
        stmt2.bind(6, mdm.id());
        stmt2.execDML();
        ins_mdm = 1;
        ins_dm = 1;
      } else {
        ins_dm = 1;
      }
    }

    if (ins_mdm > 0 && ins_dm > 0) {
      // db_->execDML("commit transaction;");
      return kSuccess;
    } else {
      // db_->execDML("rollback transaction;");
      return kAddElementError;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
  return kSuccess;
}

int PdDir::ModifyMetaDataMap(const std::string &ser_mdm,
                             const std::string &ser_dm) {
  if (ser_dm == "")  // i.e. a dir
    return kModifyElementError;

  MetaDataMap mdm;
  DataMap dm;
  if (!mdm.ParseFromString(ser_mdm))
    return kParseDataMapError;
  if (!dm.ParseFromString(ser_dm))
    return kParseDataMapError;

  int id = GetIdFromName(mdm.display_name());
  if (id < 0) {
#ifdef DEBUG
    // printf("Didn't find the mdm.\n");
#endif
    return kDBCantFindFile;
  }
  try {
    std::string s_ = "update mdm set type = ?, stats = ?, tag = ?, ";
    s_ += "file_size_high = ?, file_size_low = ?, last_modified = ?, ";
    s_ += "last_access = ? where id = ?;";
    CppSQLite3Statement stmt = db_->compileStatement(s_.c_str());
    stmt.bind(1, mdm.type());
    stmt.bind(2, mdm.stats().c_str());
    stmt.bind(3, mdm.tag().c_str());
    stmt.bind(4, mdm.file_size_high());
    stmt.bind(5, mdm.file_size_low());
    boost::uint32_t current_time = base::get_epoch_time();
    // stmt.bind(6, (const unsigned char)current_time);
    // stmt.bind(7, (const unsigned char)current_time);
    stmt.bind(6, static_cast<int>(current_time));
    stmt.bind(7, static_cast<int>(current_time));
    stmt.bind(8, id);
    int modified_elements = stmt.execDML();
    stmt.finalize();

    if (modified_elements != 1) {
#ifdef DEBUG
      // printf("Updated mdm wrong: %i\n", modified_elements_);
#endif
      return kModifyElementError;
    }

    CppSQLite3Statement stmt1 = db_->compileStatement(
        "update dm set file_hash = ?, ser_dm = ? where id = ?;");
    stmt1.bind(1, base::EncodeToHex(dm.file_hash()).c_str());
    stmt1.bind(2, base::EncodeToHex(ser_dm).c_str());
    stmt1.bind(3, id);
    modified_elements = stmt1.execDML();
    stmt1.finalize();
    if (modified_elements < 1) {
#ifdef DEBUG
      // printf("Updated dm wrong: %i\n", modified_elements_);
#endif
      return kModifyElementError;
    }
    return kSuccess;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::RemoveElement(const std::string &file_name) {
  try {
    bool flag_dm = false;
    bool flag_mdm = false;
    int rows, type;

    int id = GetIdFromName(file_name);
    if (id < 0) {
#ifdef DEBUG
      // printf("Didn't find the mdm.\n");
#endif
      return kDBCantFindFile;
    }

    std::string s = "select type from mdm where id=" + base::itos(id) + ";";
#ifdef DEBUG
    // printf("%s\n", s.c_str());
#endif
    CppSQLite3Query q_mdm = db_->execQuery(s.c_str());
    type = q_mdm.getIntField(0);
    q_mdm.finalize();

    // delete dm for files only
    if (ItemType(type) == REGULAR_FILE ||
        ItemType(type) == SMALL_FILE ||
        ItemType(type) == EMPTY_FILE) {
      s = "delete from dm where id=" + base::itos(id) + ";";
      rows = db_->execDML(s.c_str());
      if (rows > 0) {
        flag_dm = true;
      }
    } else {
      flag_dm = true;
    }

    // delete metadatamap
    s = "delete from mdm where id=" + base::itos(id) + ";";
    rows = db_->execDML(s.c_str());
    if (rows>0)
      flag_mdm = true;

    if (flag_dm && flag_mdm)
      return kSuccess;
    return kRemoveElementError;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::ListFolder(std::map<std::string, ItemType> *children) {
  try {
    std::string s = "select display_name, type from mdm;";
#ifdef DEBUG
    // printf("%s\n", s.c_str());
#endif
    CppSQLite3Query q_mdm = db_->execQuery(s.c_str());
    while (!q_mdm.eof()) {
#ifdef DEBUG
      // printf("%s\n", q_mdm.getStringField(0).c_str());
#endif
      children->insert(std::pair<std::string, ItemType>(\
        q_mdm.getStringField(0), ItemType(q_mdm.getIntField(1))));
      q_mdm.nextRow();
    }
    q_mdm.finalize();
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
  return kSuccess;
}

int PdDir::ListSubDirs(std::vector<std::string> *subdirs) {
  // boost::mutex::scoped_lock lock(mutex_);
  try {
    std::string s = "select display_name, type from mdm;";
#ifdef DEBUG
    // printf("%s\n", s.c_str());
#endif
    CppSQLite3Query q_mdm = db_->execQuery(s.c_str());
    while (!q_mdm.eof()) {
#ifdef DEBUG
      // printf("%s\n", q_mdm.getStringField(0).c_str());
#endif
      if (q_mdm.getIntField(1) == 4 || q_mdm.getIntField(1) == 5)
        subdirs->push_back(q_mdm.getStringField(0));
      q_mdm.nextRow();
    }
    q_mdm.finalize();
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
  return kSuccess;
}

int PdDir::GetDataMapFromHash(const std::string &file_hash,
                              std::string *ser_dm) {
  try {
    std::string s = "select ser_dm from dm where file_hash='" +
                    base::EncodeToHex(file_hash) + "';";
    CppSQLite3Query q_dm = db_->execQuery(s.c_str());
    if (q_dm.eof()) {
#ifdef DEBUG
      printf("Couldn't find file.\n");
#endif
      *ser_dm = "";
      return kDBCantFindFile;
    } else {
      *ser_dm = base::DecodeFromHex(q_dm.fieldValue(
                static_cast<unsigned int>(0)));
      return kSuccess;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::GetDataMap(const std::string &file_name, std::string *ser_dm) {
  int id = GetIdFromName(file_name);
  if (id < 0)
    return kDBCantFindFile;

  try {
    std::string s = "select ser_dm from dm where id=" + base::itos(id) + ";";
    CppSQLite3Query q_dm = db_->execQuery(s.c_str());
    if (q_dm.eof()) {
#ifdef DEBUG
      printf("Couldn't find file.\n");
#endif
      *ser_dm = "";
      return kDBCantFindFile;
    } else {
      *ser_dm = base::DecodeFromHex(q_dm.fieldValue(
                static_cast<unsigned int>(0)));
      return kSuccess;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::GetMetaDataMap(const std::string &file_name, std::string *ser_mdm) {
  // boost::mutex::scoped_lock lock(mutex1_);
#ifdef DEBUG
  // printf("\t\tPdDir::GetMetaDataMap %s\n", file_name.c_str());
#endif
  int id = GetIdFromName(file_name);
  if (id < 0)
    return kDBCantFindFile;

  try {
    std::string file_hash;
    std::string s = "select file_hash from dm where id=" + base::itos(id) + ";";
    CppSQLite3Query q_dm = db_->execQuery(s.c_str());
    if (q_dm.eof())
      file_hash = "";
    else
      file_hash = base::DecodeFromHex(q_dm.fieldValue(
                  static_cast<unsigned int>(0)));

    s = "select * from mdm where id=" + base::itos(id) + ";";
    CppSQLite3Query q_mdm = db_->execQuery(s.c_str());
    if (q_mdm.eof()) {
#ifdef DEBUG
      printf("Couldn't find file.\n");
#endif
      *ser_mdm = "";
      return kDBCantFindFile;
    } else {
      MetaDataMap mdm;
      mdm.set_id(q_mdm.getIntField(0));
      mdm.set_display_name(q_mdm.fieldValue(2));
      mdm.set_type(ItemType(q_mdm.getIntField(3)));
      mdm.add_file_hash(file_hash);
      mdm.set_stats(q_mdm.fieldValue(4));
      mdm.set_tag(q_mdm.fieldValue(5));
      mdm.set_file_size_high(base::stoi_ul(q_mdm.fieldValue(6)));
      mdm.set_file_size_low(base::stoi_ul(q_mdm.fieldValue(7)));
      mdm.set_creation_time(base::stoi_ul(q_mdm.fieldValue(8)));
      mdm.set_last_modified(base::stoi_ul(q_mdm.fieldValue(9)));
      mdm.set_last_access(base::stoi_ul(q_mdm.fieldValue(10)));
      mdm.SerializeToString(ser_mdm);
      return kSuccess;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::ChangeTime(const std::string &file_name, char time_type) {
  int id = GetIdFromName(file_name);
  if (id < 0)
    return kDBCantFindFile;

  std::string time_field;
  switch (time_type) {
  case 'C':
    time_field = "creation_time";
    break;
  case 'M':
    time_field = "last_modified";
    break;
  case 'A':
    time_field = "last_access";
    break;
  default:
    break;
  }

  try {
    boost::uint32_t current_time = base::get_epoch_time();
    std::string s = "update mdm set " + time_field + " = ? where id = ?;";
    CppSQLite3Statement stmt = db_->compileStatement(s.c_str());
    // stmt.bind(1, (const unsigned char)current_time);
    stmt.bind(1, static_cast<int>(current_time));
    stmt.bind(2, id);
    int modified_elements_ = stmt.execDML();
    stmt.finalize();

    if (modified_elements_ != 1) {
#ifdef DEBUG
      // printf("Updated mdm wrong: %i\n", modified_elements_);
#endif
      return kModifyElementError;
    }
    return 0;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return kDBReadWriteException;
  }
}

int PdDir::ChangeCtime(const std::string &file_name) {
  return ChangeTime(file_name, 'C');
}

int PdDir::ChangeMtime(const std::string &file_name) {
  return ChangeTime(file_name, 'M');
}

int PdDir::ChangeAtime(const std::string &file_name) {
  return ChangeTime(file_name, 'A');
}

}  // namespace maidsafe
