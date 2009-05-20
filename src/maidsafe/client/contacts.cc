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
#include "maidsafe/client/contacts.h"
#include <boost/filesystem.hpp>
#include "maidsafe/maidsafe-dht.h"

namespace fs = boost::filesystem;

namespace maidsafe {

//  Languages
int Languages::FindLanguage(const int &id, std::string &language) {
  CppSQLite3DB db;
  std::string dbName("");
  try {
    db.open(dbName.c_str());
    std::string query = "select language from language_table where id="
      + base::itos(id) + ";";
    CppSQLite3Query q = db.execQuery(query.c_str());
    if (q.eof())
      return -6;
    language = q.getStringField(0);
    db.close();
    return 0;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    try {
      db.close();
    }
    catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
      printf("%i: %s\n", e.errorCode(), e.errorMessage());
      printf("DB probably never opened.\n");
#endif
    }
    return -6;
  }
}

int Languages::FindLanguageId(const std::string &language, int &id) {
  CppSQLite3DB db;
  std::string dbName("");
  try {
    db.open(dbName.c_str());
    std::string query =
      "select language_id from language_table where language='" +
      language + "';";
    CppSQLite3Query q = db.execQuery(query.c_str());
    if (q.eof())
      return -7;
    id = q.getIntField(0);
    db.close();
    return 0;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    try {
      db.close();
    }
    catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
      printf("%i: %s\n", e.errorCode(), e.errorMessage());
      printf("DB probably never opened.\n");
#endif
    }
    return -7;
  }
}

//  Countries
int Countries::FindCountry(const int &id, std::string &country) {
  CppSQLite3DB db;
  std::string dbName("");
  try {
    db.open(dbName.c_str());
    std::string query = "select country from country_table where id="
      + base::itos(id) + ";";
    CppSQLite3Query q = db.execQuery(query.c_str());
    if (q.eof())
      return -8;
    country = q.getStringField(0);
    db.close();
    return 0;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    try {
      db.close();
    }
    catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
      printf("%i: %s\n", e.errorCode(), e.errorMessage());
      printf("DB probably never opened.\n");
#endif
    }
    return -8;
  }
}

int Countries::FindCountryId(const std::string &country, int &id) {
  CppSQLite3DB db;
  std::string dbName("");
  try {
    db.open(dbName.c_str());
    std::string query =
      "select country_id from language_table where language='" +
      country + "';";
    CppSQLite3Query q = db.execQuery(query.c_str());
    if (q.eof())
      return -9;
    id = q.getIntField(0);
    db.close();
    return 0;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    try {
      db.close();
    }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
    printf("DB probably never opened.\n");
#endif
    }
    return -9;
  }
}

//  Contacts
Contacts::Contacts() :pub_name_(""), pub_key_(""), full_name_(""),
  office_phone_(""), birthday_(""), gender_('U'), language_(-1),
  country_(-1), city_(""), confirmed_('\0'), rank_(0),  last_contact_(-1) { }

Contacts::Contacts(const std::vector<std::string> &attributes)
    :pub_name_(""), pub_key_(""), full_name_(""),
    office_phone_(""), birthday_(""), gender_('U'), language_(-1),
    country_(-1), city_(""), confirmed_('\0'), rank_(0), last_contact_(-1) {
  pub_name_ = attributes[0];
  pub_key_ = attributes[1];
  full_name_ = attributes[2];
  office_phone_ = attributes[3];
  birthday_ = attributes[4];
  gender_ = attributes[5].at(0);
  language_ = base::stoi(attributes[6]);
  country_ = base::stoi(attributes[7]);
  city_ = attributes[8];
  confirmed_ = attributes[9].at(0);
  rank_ = base::stoi(attributes[10]);
  last_contact_ = base::stoi(attributes[11]);
}

//  ContactsHandler
int ContactsHandler::CreateContactDB(const std::string &dbName) {
  int n = Connect(dbName);
  if (n)
    return n;

  try {
    // db_->execDML("drop table if exists share_contacts;");
    std::string create_db("create table share_contacts( ");
    create_db += "pub_name varchar(100) primary key, ";
    create_db += "pub_key varchar(100) not null, ";
    create_db += "full_name varchar(100), ";
    create_db += "office_phone varchar(20), ";
    create_db += "birthday varchar(20), ";
    create_db += "gender char(1), ";
    create_db += "language int, ";
    create_db += "country int, ";
    create_db += "city varchar(30), ";
    create_db += "confirmed bool not null, ";
    create_db += "rank int default 0, ";
    create_db += "last_contact int default -1);";
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

int ContactsHandler::Connect(const std::string &dbName) {
  db_.reset(new CppSQLite3DB());
  try {
    db_->open(dbName.c_str());
    return 0;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    return -1;
  }
}

int ContactsHandler::Close() {
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
    return -2;
  }
}

int ContactsHandler::AddContact(const std::string &dbName, Contacts &sc) {
#ifdef DEBUG
  // printf("Add Contact LastContact: %i\n", sc.LastContact());
#endif
  int n = Connect(dbName);
  if (n)
    return n;

  try {
    CppSQLite3Statement stmt = db_->compileStatement(
      "insert into share_contacts values(?,?,?,?,?,?,?,?,?,?,?,?);");
    stmt.bind(1, sc.PublicName().c_str());
    stmt.bind(2, sc.PublicKey().c_str());
    stmt.bind(3, sc.FullName().c_str());
    stmt.bind(4, sc.OfficePhone().c_str());
    stmt.bind(5, sc.Birthday().c_str());
    stmt.bind(6, sc.Gender());
    stmt.bind(7, sc.Language());
    stmt.bind(8, sc.Country());
    stmt.bind(9, sc.City().c_str());
    stmt.bind(10, sc.Confirmed());
    stmt.bind(11, sc.Rank());
    stmt.bind(12, sc.LastContact());
    n = stmt.execDML();
    if (n != 1)
      return -3;
    stmt.reset();
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -3;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int ContactsHandler::DeleteContact(const std::string &dbName, Contacts &sc) {
  int n = Connect(dbName);
  if (n)
    return n;

  try {
    CppSQLite3Statement stmt = db_->compileStatement(
      "delete from share_contacts where pub_name=?;");
    stmt.bind(1, sc.PublicName().c_str());
    n = stmt.execDML();
    stmt.reset();
    if (n != 1)
      return -4;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -4;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int ContactsHandler::UpdateContact(const std::string &dbName, Contacts &sc) {
#ifdef DEBUG
  printf("In SQL Update Contact\n");
#endif

  int n = Connect(dbName);
  if (n)
    return n;

  //  Evaluation of elements to update
  bool b_pub_key = false;
  bool b_full_name = false;
  bool b_office_phone = false;
  bool b_birthday = false;
  bool b_gender = false;
  bool b_language = false;
  bool b_country = false;
  bool b_city = false;
  bool b_confirmed = false;
  bool b_rank = false;
  bool b_last_contact = false;

  bool first = true;

  std::string update_query("update share_contacts set ");
  if (sc.PublicKey() != "") {
    if (first) {
      first = false;
      update_query += "pub_key=?";
    } else {
      update_query += " ,pub_key=?";
    }
    b_pub_key = true;
  }
  if (sc.FullName() != "") {
    if (first) {
      first = false;
      update_query += "full_name=?";
    } else {
      update_query += " ,full_name=?";
    }
    b_full_name = true;
  }
  if (sc.OfficePhone() != "") {
    if (first) {
      first = false;
      update_query += "office_phone=?";
    } else {
      update_query += " ,office_phone=?";
    }
    b_office_phone = true;
  }
  if (sc.Birthday() != "") {
    if (first) {
      first = false;
      update_query += "birthday=?";
    } else {
      update_query += " ,birthday=?";
    }
    b_birthday = true;
  }
  if (sc.Gender() != 'U') {
    if (first) {
      first = false;
      update_query += "gender=?";
    } else {
      update_query += " ,gender=?";
    }
    b_gender = true;
  }
  if (sc.Language() != -1) {
    if (first) {
      first = false;
      update_query += "language=?";
    } else {
      update_query += " ,language=?";
    }
    b_language = true;
  }
  if (sc.Country() != -1) {
    if (first) {
      first = false;
      update_query += "country=?";
    } else {
      update_query += " ,country=?";
    }
    b_country = true;
  }
  if (sc.City() != "") {
    if (first) {
      first = false;
      update_query += "city=?";
    } else {
      update_query += " ,city=?";
    }
    b_city = true;
  }
  if (sc.Confirmed() != '\0') {
    if (first) {
      first = false;
      update_query += "confirmed=?";
    } else {
      update_query += " ,confirmed=?";
    }
    b_confirmed = true;
  }
  if (sc.Rank() != 0) {
    if (first) {
      first = false;
      update_query += "rank=?";
    } else {
      update_query += " ,rank=?";
    }
    b_confirmed = true;
    b_rank = true;
  }
  if (sc.LastContact() != -1) {
    if (first) {
      first = false;
      update_query += "last_contact=?";
    } else {
      update_query += " ,last_contact=?";
    }
    b_confirmed = true;
    b_last_contact = true;
  }
  update_query += " where pub_name=?;";

#ifdef DEBUG
  printf("SQL Update Contact: %s\n", update_query.c_str());
#endif

  try {
    int element = 1;
    CppSQLite3Statement stmt = db_->compileStatement(update_query.c_str());

    if (b_pub_key) {
      stmt.bind(element, sc.PublicKey().c_str());
      ++element;
    }
    if (b_full_name) {
      stmt.bind(element, sc.FullName().c_str());
      ++element;
    }
    if (b_office_phone) {
      stmt.bind(element, sc.OfficePhone().c_str());
      ++element;
    }
    if (b_birthday) {
      stmt.bind(element, sc.Birthday().c_str());
      ++element;
    }
    if (b_gender) {
      stmt.bind(element, sc.Gender());
      ++element;
    }
    if (b_language) {
      stmt.bind(element, sc.Language());
      ++element;
    }
    if (b_country) {
      stmt.bind(element, sc.Country());
      ++element;
    }
    if (b_city) {
      stmt.bind(element, sc.City().c_str());
      ++element;
    }
    if (b_confirmed) {
      stmt.bind(element, sc.Confirmed());
      ++element;
    }
    if (b_rank) {
      stmt.bind(element, sc.Rank());
      ++element;
    }
    if (b_last_contact) {
      stmt.bind(element, sc.LastContact());
      ++element;
    }

    stmt.bind(element, sc.PublicName().c_str());
    n = stmt.execDML();
    stmt.reset();
    if (n != 1)
      return -5;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -5;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int ContactsHandler::GetContactList(const std::string &dbName,
  std::vector<Contacts> &list, const std::string &pub_name,
  bool like, int type) {
  int n = Connect(dbName);
  if (n)
    return n;

  std::string query("select * from share_contacts");
  switch (type) {
    case 0: if (pub_name != "") {
              if (like)
                query += " where pub_name like '%"+pub_name+"%'";
              else
                query += " where pub_name = '"+pub_name+"'";
            }
            break;
    case 1: query += " order by rank desc"; break;
    case 2: query += " order by last_contact desc"; break;
  }
  query += ";";

  try {
    int rows = 0;
    CppSQLite3Query q = db_->execQuery(query.c_str());
    while (!q.eof() && rows < 50) {
      Contacts *sc = new Contacts();
      sc->SetPublicName(q.getStringField(0));
      sc->SetPublicKey(q.getStringField(1));
      sc->SetFullName(q.getStringField(2));
      sc->SetOfficePhone(q.getStringField(3));
      sc->SetBirthday(q.getStringField(4));
      sc->SetGender(q.getIntField(5));
      sc->SetLanguage(q.getIntField(6));
      sc->SetCountry(q.getIntField(7));
      sc->SetCity(q.getStringField(8));
      sc->SetConfirmed(q.getIntField(9));
      sc->SetRank(q.getIntField(10));
      sc->SetLastContact(q.getIntField(11));
      list.push_back(*sc);
      delete sc;
      q.nextRow();
      ++rows;
    }
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -10;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

int ContactsHandler::SetLastContactRank(const std::string &dbName,
  Contacts &sc) {
  int n = Connect(dbName);
  if (n)
    return n;

  std::string query("select * from share_contacts");
  query += " where pub_name='"+sc.PublicName()+"'";
  query += ";";

  int current_rank = -2;

  try {
    CppSQLite3Query q = db_->execQuery(query.c_str());
    current_rank = q.getIntField(10);
    q.finalize();
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -10;
  }

  ++current_rank;

  try {
    CppSQLite3Statement stmt = db_->compileStatement(
      "update share_contacts set last_contact=?, rank=? where pub_name=?;");
    stmt.bind(1, static_cast<int>(base::get_epoch_time()));
    stmt.bind(2, current_rank);
    stmt.bind(3, sc.PublicName().c_str());
    n = stmt.execDML();
    stmt.reset();
    if (n != 1)
      return -11;
  }
  catch(CppSQLite3Exception& e) {  //NOLINT
#ifdef DEBUG
    printf("%i: %s\n", e.errorCode(), e.errorMessage());
#endif
    n = Close();
    return -11;
  }

  n = Close();
  if (n)
    return n;

  return 0;
}

}  // namespace maidsafe
