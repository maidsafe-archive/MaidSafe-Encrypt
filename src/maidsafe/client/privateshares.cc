/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */
#include "maidsafe/client/privateshares.h"
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace maidsafe {

//  PrivateShare
PrivateShare::PrivateShare() : name_(""),
    msid_(""), msid_pub_key_(""), msid_priv_key_(""),
    participants_(0) {
}

PrivateShare::PrivateShare(const std::vector<std::string> &attributes,
    std::list<ShareParticipants> participants) : name_(attributes[0]),
    msid_(attributes[1]), msid_pub_key_(attributes[2]),
    msid_priv_key_(attributes[3]),
    participants_(participants) {
}

//  PrivateShareHandler
int PrivateShareHandler::Connect(const std::string &dbName) {
  db_.reset(new CppSQLite3DB());
  try {
    db_->open(dbName.c_str());
    return 0;
  }
  catch(CppSQLite3Exception& e) {  // NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    return -2201;
  }
}

int PrivateShareHandler::Close() {
  try {
    db_->close();
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    return (-1*e.errorCode()-1000);
  }
  try {
    // delete db_;
    return 0;
  }
  catch(const std::exception& e) {
    return -2202;
  }
}

int PrivateShareHandler::CreatePrivateShareDB(const std::string &dbName) {
  int n = Connect(dbName);
  if (n)
    return n;

  try {
    std::string create_db("create table private_share( ");
    create_db += "name varchar(100) primary key, ";
    create_db += "MSID varchar(256) not null, ";
    create_db += "pub_key varchar(10240) not null, ";
    create_db += "priv_key varchar(10240));";
    db_->execDML(create_db.c_str());
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return (-1*e.errorCode()-1000);
  }

  try {
    std::string create_db("create table private_share_contact( ");
    create_db += "MSID varchar(256) not null, ";
    create_db += "pub_key varchar(10240) not null, ";
    create_db += "contact varchar(512) not null,";
    create_db += "role char(1));";
    db_->execDML(create_db.c_str());
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return (-1*e.errorCode()-1000);
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int PrivateShareHandler::GetPrivateShareList(const std::string &dbName,
    std::list<PrivateShare> *participants,
    const std::string &value, const int &type) {
  int n = Connect(dbName);
  if (n)
    return n;

  std::string query("");
  switch (type) {
    case 0: query = "select * from private_share where name = '" +
              value + "';";
            break;
    case 1: query = "select * from private_share where MSID = '" +
              value + "';";
            break;
    case 2: query = "select * from private_share_contact where contact = '" +
              value + "';";
            break;
    default: query = "select * from private_share;"; break;
  }

  try {
    CppSQLite3Query q = db_->execQuery(query.c_str());
    while (!q.eof()) {
      if (type != 2) {
        query = "select contact, pub_key, role from private_share_contact";
        query += " where MSID = '";
        query += q.getStringField(1);
        query += "';";
        CppSQLite3Query q1 = db_->execQuery(query.c_str());
        std::list<ShareParticipants> r_list;
        while (!q1.eof()) {
          maidsafe::ShareParticipants sp;
          sp.id = q1.getStringField(0);
          sp.public_key = q1.getStringField(1);
          std::string role(q1.getStringField(2));
          sp.role = role.at(0);
          r_list.push_back(sp);
          q1.nextRow();
        }
        std::vector<std::string> v;
        v.push_back(q.getStringField(0));
        v.push_back(q.getStringField(1));
        v.push_back(q.getStringField(2));
        v.push_back(q.getStringField(3));
        maidsafe::PrivateShare ps(v, r_list);
        participants->push_back(ps);
        q1.finalize();
      } else {
        query = "select * from private_share";
        query += " where MSID = '";
        query += q.getStringField(0);
        query += "';";
        CppSQLite3Query q1 = db_->execQuery(query.c_str());
        std::list<ShareParticipants> r_list;
        maidsafe::ShareParticipants sp;
        sp.id = q.getStringField(2);
        sp.public_key = q.getStringField(1);
        std::string role(q.getStringField(3));
        sp.role = role.at(0);
        r_list.push_back(sp);
        while (!q1.eof()) {
          std::vector<std::string> v;
          v.push_back(q.getStringField(0));
          v.push_back(q.getStringField(1));
          v.push_back(q.getStringField(2));
          v.push_back(q.getStringField(3));
          maidsafe::PrivateShare ps(v, r_list);
          participants->push_back(ps);
        }
        q1.finalize();
      }
      q.nextRow();
    }
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -2204;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int PrivateShareHandler::AddPrivateShare(const std::string &dbName,
    const std::vector<std::string> &attributes,
    std::list<ShareParticipants> *participants) {
  if (attributes.size() != 4 || participants->size() == 0) {
#ifdef DEBUG
    printf("Aqui te la pelaste: %i -- %i\n", attributes.size(),
      participants->size());
#endif
    return -2205;
  }
  maidsafe::PrivateShare ps(attributes, *participants);
  int n = Connect(dbName);
  if (n)
    return n;

  try {
    CppSQLite3Statement stmt = db_->compileStatement(
        "insert into private_share values(?,?,?,?);");
    stmt.bind(1, ps.Name().c_str());
    stmt.bind(2, ps.Msid().c_str());
    stmt.bind(3, ps.MsidPubKey().c_str());
    stmt.bind(4, ps.MsidPriKey().c_str());
    n = stmt.execDML();
    stmt.finalize();
    if (n != 1) {
#ifdef DEBUG
      printf("Aca te la pelaste\n");
#endif
      return -2205;
    }
    stmt.reset();
    while (!participants->empty()) {
      maidsafe::ShareParticipants r;
      r = participants->front();
      participants->pop_front();
      CppSQLite3Statement stmt1 = db_->compileStatement(
          "insert into private_share_contact values(?,?,?,?);");
      stmt1.bind(1, ps.Msid().c_str());
      stmt1.bind(2, r.public_key.c_str());
      stmt1.bind(3, r.id.c_str());
      stmt1.bind(4, r.role);
      n = stmt1.execDML();
      stmt1.finalize();
      if (n != 1) {
#ifdef DEBUG
        printf("Aculla te la pelaste\n");
#endif
        return -2205;
      }
      stmt1.reset();
    }
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -2205;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int PrivateShareHandler::AddReceivedShare(const std::string &dbName,
    const std::vector<std::string> &attributes) {
  if (attributes.size() != 4) {
    printf("Aqui te la pelaste\n");
    return -2206;
  }
  std::list<ShareParticipants> participants;
  maidsafe::PrivateShare ps(attributes, participants);
  int n = Connect(dbName);
  if (n)
    return n;

  try {
    CppSQLite3Statement stmt = db_->compileStatement(
        "insert into private_share values(?,?,?,?);");
    stmt.bind(1, ps.Name().c_str());
    stmt.bind(2, ps.Msid().c_str());
    stmt.bind(3, ps.MsidPubKey().c_str());
    stmt.bind(4, ps.MsidPriKey().c_str());
    n = stmt.execDML();
    stmt.finalize();
    if (n != 1) {
      printf("Aca te la pelaste\n");
      return -2206;
    }
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -2206;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int PrivateShareHandler::DeletePrivateShare(const std::string &dbName,
    const std::string &value, const int &field) {
  int n = Connect(dbName);
  if (n)
    return n;
  std::string msid(value);
  std::string query("delete from");
  switch (field) {
    case 0: {
              query += " private_share where MSID=?;";
            } break;
    case 1: {
              std::list<maidsafe::PrivateShare> participants;
              unsigned int zero(0);
              n = GetPrivateShareList(dbName, &participants, value, zero);
              if (n == 0 && participants.size() == 1) {
                maidsafe::PrivateShare ps = participants.front();
                msid = ps.Msid();
                query += " private_share where name=?;";
                n = Connect(dbName);
                if (n)
                  return n;
              } else {
#ifdef DEBUG
                printf("Didn't get proper list back.\n");
#endif
                return -2207;
              }
            } break;
    default: break;
  }
  try {
    CppSQLite3Statement stmt = db_->compileStatement(query.c_str());
    stmt.bind(1, value.c_str());
    n = stmt.execDML();
    stmt.reset();
    if (n != 1) {
#ifdef DEBUG
      // printf("me carga la riata\n");
#endif
      return -2207;
    }
    CppSQLite3Statement stmt1 = db_->compileStatement(
      "delete from private_share_contact where MSID=?");
    stmt1.bind(1, msid.c_str());
    n = stmt1.execDML();
    stmt1.reset();
    if (n < 1) {
#ifdef DEBUG
      // printf("me carga la riata por segunda vez: %i\n", n);
#endif
      return -2207;
    }
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -2207;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int PrivateShareHandler::AddContactsToPrivateShare(
    const std::string &dbName,
    std::list<ShareParticipants> *participants,
    const std::string &value, const int &type) {
  std::list<maidsafe::PrivateShare> share_list;
  std::string msid(value);
  if (type == 1) {  // Need to get MSID
    GetPrivateShareList(dbName, &share_list, value, 0);
    if (share_list.size() != 1)
      return -2208;
    maidsafe::PrivateShare ps = share_list.front();
    msid = ps.Msid();
  }
  int n = Connect(dbName);
  if (n)
    return n;
  try {
    while (!participants->empty()) {
      maidsafe::ShareParticipants r;
      r = participants->front();
      participants->pop_front();
      CppSQLite3Statement stmt1 = db_->compileStatement(
          "insert into private_share_contact values(?,?,?,?);");
      stmt1.bind(1, msid.c_str());
      stmt1.bind(2, r.public_key.c_str());
      stmt1.bind(3, r.id.c_str());
      stmt1.bind(4, r.role);
      n = stmt1.execDML();
      stmt1.finalize();
      if (n != 1) {
        return -2208;
      }
      stmt1.reset();
    }
  }
  catch(CppSQLite3Exception& ce) {  //NOLINT
    std::cout << ce.errorCode() << ": " << ce.errorMessage() << std::endl;
    n = Close();
    return -2208;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int PrivateShareHandler::DeleteContactsFromPrivateShare(
    const std::string &dbName,
    std::list<ShareParticipants> *participants) {
  int n = Connect(dbName);
  if (n)
    return n;
  try {
    while (!participants->empty()) {
      maidsafe::ShareParticipants r = participants->front();
      participants->pop_front();
      CppSQLite3Statement stmt1 = db_->compileStatement(
          "delete from private_share_contact where contact=?;");
      stmt1.bind(1, r.id.c_str());
      n = stmt1.execDML();
      stmt1.finalize();
      if (n != 1) {
        return -2209;
      }
      stmt1.reset();
    }
  }
  catch(CppSQLite3Exception& ce) {  //NOLINT
    std::cout << ce.errorCode() << ": " << ce.errorMessage() << std::endl;
    n = Close();
    return -2209;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

}   // namespace
