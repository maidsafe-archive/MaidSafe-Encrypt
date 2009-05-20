/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class for manipulating database of user keys
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

#include "maidsafe/client/keyatlas.h"

#include <stdint.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <exception>
#include <map>

#include "boost/filesystem.hpp"

#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"
#include "protobuf/datamaps.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {


KeyAtlas::KeyAtlas(const std::string &db_name,
                   db_init_flag flag_,
                   int *result_): db_name_(db_name), db_(new CppSQLite3DB()) {
  *result_ = Init(flag_);
}


KeyAtlas::~KeyAtlas() {
  DisconnectKeysDb();
}


int KeyAtlas::Init(db_init_flag flag_) {
  switch (flag_) {
    case CONNECT:
      if (ConnectKeysDb())
        return -1;
      break;
    case CREATE:
      if (CreateKeysDb())
        return -1;
      break;
    case DISCONNECT:
      if (DisconnectKeysDb())
        return -1;
      break;
    default:
      return -1;
  }
  return 0;
}


int KeyAtlas::ConnectKeysDb() {
  if (!fs::exists(db_name_))
    return -1;
  try {
    db_->open(db_name_.c_str());
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return -1;
  }
  return 0;
}


int KeyAtlas::CreateKeysDb() {
  if (fs::exists(db_name_))
    return -3;
  try {
    db_->open(db_name_.c_str());
    // create table structure
    db_->execDML("drop table if exists key");
    std::string s = "create table key(type varchar(280), id char(64), ";
    s += "private_key varchar(2048), public_key varchar(2048), ";
    s += "primary key(type));";
    db_->execDML(s.c_str());
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return -1;
  }
  return 0;
}


int KeyAtlas::DisconnectKeysDb() {
  try {
    db_->close();
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return -1;
  }
  return 0;
}


int KeyAtlas::AddKeys(const std::string &package_type,
                      const std::string &package_id,
                      const std::string &private_key,
                      const std::string &public_key) {
  try {
    CppSQLite3Statement stmt;
    std::string s = "select * from key where type='"+package_type+"';";
    CppSQLite3Query q_keys = db_->execQuery(s.c_str());
    int ins_keys = 0;
    if (q_keys.eof()) {  // key is not there, add it to the keys
      stmt = db_->compileStatement("insert into key values(?,?,?,?);");
      stmt.bind(1, package_type.c_str());
      stmt.bind(2, package_id.c_str());
      stmt.bind(3, private_key.c_str());
      stmt.bind(4, public_key.c_str());
      ins_keys = stmt.execDML();
    } else {
      s = "update key set id = '"+package_id+"', private_key = ";
      s += "'"+private_key+"', public_key = '"+public_key+"' where type = ";
      s += "'"+package_type+"';";
      ins_keys = db_->execDML(s.c_str());
    }

    if (ins_keys == 1)
      return 0;
    else
      return -1;
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return -1;
  }
}  // AddKeys


std::string KeyAtlas::GetKeyData(const std::string &package_type,
                                 char data_type) {
  std::string data_field;
  switch (data_type) {
  case 'I':
    data_field = "id";
    break;
  case 'R':
    data_field = "private_key";
    break;
  case 'U':
    data_field = "public_key";
    break;
  default:
    break;
  }
  try {
    std::string s = "select "+data_field+" from key where type='";
    s += package_type+"';";
    CppSQLite3Query q_keys = db_->execQuery(s.c_str());
    if (!q_keys.eof()) {
      return q_keys.fieldValue(static_cast<unsigned int>(0));
    } else {
      return "";
    }
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return "";
  }
}  // GetKeyData


std::string KeyAtlas::GetPackageID(const std::string &package_type) {
  return GetKeyData(package_type, 'I');
}


std::string KeyAtlas::GetPrivateKey(const std::string &package_type) {
  return GetKeyData(package_type, 'R');
}


std::string KeyAtlas::GetPublicKey(const std::string &package_type) {
  return GetKeyData(package_type, 'U');
}


int KeyAtlas::RemoveKeys(const std::string &package_type) {
  try {
    std::string s = "delete from key where type = '"+package_type+"';";
    int del_key = db_->execDML(s.c_str());
    if (del_key == 1)
      return 0;
    else
      return -1;
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return -1;
  }
}


void KeyAtlas::GetKeyRing(std::list<Key_Type> *keyring) {
  try {
    const int kBuffSize = 8;
    char buffer1_[kBuffSize];
    char buffer2_[kBuffSize];
    std::string mpid_ = base::itos(MPID);
    std::string pmid_ = base::itos(PMID);
    snprintf(buffer1_, kBuffSize, "%s", mpid_.c_str());
    snprintf(buffer2_, kBuffSize, "%s", pmid_.c_str());
    std::string out1_ = buffer1_;
    std::string out2_ = buffer2_;
    std::string s = "select * from key where type='"+out1_+"' or type='";
    s += out2_+"';";
    CppSQLite3Query q_keys1 = db_->execQuery(s.c_str());

    // define a row
    Key_Type key_ring_row;

    while (!q_keys1.eof()) {
      std::string type = q_keys1.fieldValue(static_cast<unsigned int>(0));
      PacketType ptype = (PacketType)base::stoi(type);
      key_ring_row.package_type = ptype;
      key_ring_row.id = q_keys1.fieldValue(1);
      key_ring_row.private_key = q_keys1.fieldValue(2);
      key_ring_row.public_key = q_keys1.fieldValue(3);

      keyring->push_back(key_ring_row);
      q_keys1.nextRow();
    }
    q_keys1.finalize();

    char buffer3_[kBuffSize];
    char buffer4_[kBuffSize];
    char buffer5_[kBuffSize];
    char buffer6_[kBuffSize];
    char buffer7_[kBuffSize];
    std::string anmid_ = base::itos(ANMID);
    std::string antmid_ = base::itos(ANTMID);
    std::string ansmid_ = base::itos(ANSMID);
    std::string maid_ = base::itos(MAID);
    std::string anmpid_ = base::itos(ANMPID);
    snprintf(buffer3_, kBuffSize, "%s", anmid_.c_str());
    snprintf(buffer4_, kBuffSize, "%s", antmid_.c_str());
    snprintf(buffer5_, kBuffSize, "%s", ansmid_.c_str());
    snprintf(buffer6_, kBuffSize, "%s", maid_.c_str());
    snprintf(buffer7_, kBuffSize, "%s", anmpid_.c_str());
    std::string out3_ = buffer3_;
    std::string out4_ = buffer4_;
    std::string out5_ = buffer5_;
    std::string out6_ = buffer6_;
    std::string out7_ = buffer7_;

    s = "select * from key where type='"+out3_+"' or type='"+out4_+"' or type";
    s += "='"+out5_+"' or type='"+out6_+"' or type='"+out7_+ "';";
    CppSQLite3Query q_keys2 = db_->execQuery(s.c_str());

    while (!q_keys2.eof()) {
      std::string type = q_keys2.fieldValue(static_cast<unsigned int>(0));
      PacketType ptype = (PacketType)base::stoi(type);
      key_ring_row.package_type = ptype;
      key_ring_row.id = q_keys2.fieldValue(1);
      key_ring_row.private_key = q_keys2.fieldValue(2);
      key_ring_row.public_key = q_keys2.fieldValue(3);

      keyring->push_back(key_ring_row);
      q_keys2.nextRow();
    }
    q_keys2.finalize();
    return;
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
    return;
  }
}

}  // namespace maidsafe
