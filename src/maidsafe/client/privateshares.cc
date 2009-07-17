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

// Multi Index
int PrivateShareHandler::MI_AddPrivateShare(
    const std::vector<std::string> &attributes,
    std::list<ShareParticipants> *participants) {
  if (attributes.size() != 4)
    return -2010;

  bool ro_participation = false;
  if (attributes[3] == "" && participants->empty())
    ro_participation = true;

  private_share ps(attributes[0], attributes[1], attributes[2], attributes[3]);
  pss_.insert(ps);

  if (!ro_participation) {
    while (!participants->empty()) {
      ShareParticipants sps = participants->front();
      share_participant sp(ps.msid_, sps.id, sps.public_key, sps.role);
      participants->pop_front();
      psps_.insert(sp);
    }
  }

  return 0;
}

int PrivateShareHandler::MI_DeletePrivateShare(
    const std::string &value, const int &field) {
  if (field < 0 || field > 1)
    return -2011;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2011;
    msid = (*it).msid_;
    private_share_index.erase(value);
  } else {
    typedef private_share_set::index<private_share_msid>::type
            private_share_set_by_msid;
    private_share_set_by_msid& private_share_index =
        pss_.get<private_share_msid>();
    private_share_set_by_msid::iterator it = private_share_index.find(msid);
    if (it == private_share_index.end())
      return -2011;
    private_share_index.erase(msid);
  }

  typedef private_share_participant_set::index<share_participant_msid>::type
          private_share_participant_set_by_msid;
  private_share_participant_set_by_msid& private_share_participant_index =
      psps_.get<share_participant_msid>();
  private_share_participant_set_by_msid::iterator it =
      private_share_participant_index.find(msid);
  if (it == private_share_participant_index.end())
    return -2011;
  private_share_participant_index.erase(msid);

  return 0;
}

int PrivateShareHandler::MI_AddContactsToPrivateShare(
    const std::string &value, const int &field,
    std::list<ShareParticipants> *participants) {
  if (field < 0 || field > 1)
    return -2012;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2012;
    msid = (*it).msid_;
  }

  while (!participants->empty()) {
    ShareParticipants sps = participants->front();
    share_participant sp(msid, sps.id, sps.public_key, sps.role);
    participants->pop_front();
    psps_.insert(sp);
  }

  return 0;
}

int PrivateShareHandler::MI_DeleteContactsFromPrivateShare(
    const std::string &value, const int &field,
    std::list<ShareParticipants> *participants) {
  if (field < 0 || field > 1)
    return -2013;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2013;
    msid = (*it).msid_;
  }

  while (!participants->empty()) {
    ShareParticipants sps = participants->front();
    typedef private_share_participant_set::index<share_participant_msid>::type
            private_share_participant_set_msid;
    private_share_participant_set_msid& private_share_participant_index =
        psps_.get<share_participant_msid>();
    for (private_share_participant_set_msid::iterator it =
         private_share_participant_index.find(msid); it !=
         private_share_participant_index.end(); it++) {
      if ((*it).public_name_ == sps.id)
        private_share_participant_index.erase((*it).msid_);
    }
    participants->pop_front();
  }
  return 0;
}

int PrivateShareHandler::MI_GetShareInfo(const std::string &value,
    const int &field, PrivateShare *ps) {
  if (field < 0 || field > 1)
    return -2014;
  std::string msid(value);
  std::vector<std::string> share_attributes;
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2014;
    msid = (*it).msid_;
    printf("LLEGO\n");
  } else {
    typedef private_share_set::index<private_share_msid>::type
            private_share_set_by_msid;
    private_share_set_by_msid& private_share_index =
        pss_.get<private_share_msid>();
    private_share_set_by_msid::iterator it = private_share_index.find(msid);
    if (it == private_share_index.end())
      return -2014;
    share_attributes.push_back((*it).name_);
    share_attributes.push_back((*it).msid_);
    share_attributes.push_back((*it).msid_pub_key_);
    share_attributes.push_back((*it).msid_priv_key_);
  }
  std::list<ShareParticipants> sps;
  typedef private_share_participant_set::index<share_participant_msid>::type
          private_share_participant_set_msid;
  private_share_participant_set_msid& private_share_participant_index =
      psps_.get<share_participant_msid>();
  int n = 0;
  private_share_participant_set_msid::iterator it =
       private_share_participant_index.find(msid);
  while (it != private_share_participant_index.end()) {
    printf("%d ", n);
    ShareParticipants sp;
    printf("%d ", n);
    sp.id = (*it).public_name_;
    printf("%d ", n);
    sp.public_key = (*it).public_key_;
    printf("%d ", n);
    sp.role = (*it).role_;
    printf("%d ", n);
    sps.push_back(sp);
    printf("%d ", n);
    it++;
    printf("%d\n", n);
    n++;
  }

  ps = new PrivateShare(share_attributes, sps);

  return 0;
}

int PrivateShareHandler::MI_GetShareList(std::list<private_share> *ps_list) {
  typedef private_share_set::index<private_share_name>::type
          private_share_set_name;
  private_share_set_name& private_share_index =
      pss_.get<private_share_name>();
  for (private_share_set_name::iterator it = private_share_index.begin();
       it != private_share_index.end(); it++) {
    private_share pr((*it).name_, (*it).msid_, (*it).msid_pub_key_,
                    (*it).msid_priv_key_);
    ps_list->push_back(pr);
  }
  return 0;
}

int PrivateShareHandler::MI_GetFullShareList(std::list<PrivateShare> *ps_list) {
  std::list<private_share> share_list;
  MI_GetShareList(&share_list);
  while (!share_list.empty()) {
    PrivateShare ps;
    MI_GetShareInfo(share_list.front().name_, 0, &ps);
    ps_list->push_back(ps);
  }
  return 0;
}

int PrivateShareHandler::MI_GetParticipantsList(const std::string &value,
    const int &field, std::list<share_participant> *sp_list) {
  if (field < 0 || field > 1)
    return -2015;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2015;
    msid = (*it).msid_;
  }

  typedef private_share_participant_set::index<share_participant_msid>::type
          private_share_participant_set_msid;
  private_share_participant_set_msid& private_share_participant_index =
      psps_.get<share_participant_msid>();
  for (private_share_participant_set_msid::iterator it =
       private_share_participant_index.begin(); it !=
       private_share_participant_index.end(); it++) {
    share_participant sp((*it).msid_, (*it).public_name_, (*it).public_key_,
                        (*it).role_);
    sp_list->push_back(sp);
  }
  if (sp_list->empty())
    return -2015;
  return 0;
}

}   // namespace
