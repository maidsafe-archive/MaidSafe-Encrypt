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
Contact::Contact() :pub_name_(""), pub_key_(""), full_name_(""),
  office_phone_(""), birthday_(""), gender_('U'), language_(-1),
  country_(-1), city_(""), confirmed_('\0'), rank_(0),  last_contact_(-1) { }

Contact::Contact(const std::vector<std::string> &attributes)
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
int ContactsHandler::AddContact(const std::string &pub_name,
                                   const std::string &pub_key,
                                   const std::string &full_name,
                                   const std::string &office_phone,
                                   const std::string &birthday,
                                   const char &gender,
                                   const int &language,
                                   const int &country,
                                   const std::string &city,
                                   const char &confirmed,
                                   const int &rank,
                                   const int &last_contact) {
  int lc = 0;
  if (last_contact == 0)
    lc = base::get_epoch_time();
  mi_contact mic(pub_name, pub_key, full_name, office_phone, birthday, gender,
                 language, country, city, confirmed, rank, lc);
  cs_.insert(mic);
  return 0;
}

int ContactsHandler::DeleteContact(const std::string &pub_name) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1901;
  }
  cs_.erase(pub_name);
  return 0;
}

int ContactsHandler::UpdateContact(const mi_contact &mic) {
  contact_set::iterator it = cs_.find(mic.pub_name_);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", mic.pub_name_.c_str());
#endif
    return -1902;
  }
  mi_contact local_mic = *it;
  local_mic.pub_key_ = mic.pub_key_;
  local_mic.full_name_ = mic.full_name_;
  local_mic.office_phone_ = mic.office_phone_;
  local_mic.birthday_ = mic.birthday_;
  local_mic.gender_ = mic.gender_;
  local_mic.language_ = mic.language_;
  local_mic.country_ = mic.country_;
  local_mic.city_ = mic.city_;
  local_mic.confirmed_ = mic.confirmed_;
  local_mic.rank_ = mic.rank_;
  local_mic.last_contact_ = mic.last_contact_;
  cs_.replace(it, local_mic);
  return 0;
}

int ContactsHandler::UpdateContactKey(const std::string &pub_name,
                                      const std::string &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1903;
  }
  mi_contact mic = *it;
  mic.pub_key_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactFullName(const std::string &pub_name,
                                           const std::string &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1904;
  }
  mi_contact mic = *it;
  mic.full_name_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactOfficePhone(const std::string &pub_name,
                                              const std::string &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1905;
  }
  mi_contact mic = *it;
  mic.office_phone_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactBirthday(const std::string &pub_name,
                                           const std::string &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1906;
  }
  mi_contact mic = *it;
  mic.birthday_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactGender(const std::string &pub_name,
                                         const char &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1907;
  }
  mi_contact mic = *it;
  mic.gender_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactLanguage(const std::string &pub_name,
                                           const int &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1908;
  }
  mi_contact mic = *it;
  mic.language_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactCountry(const std::string &pub_name,
                                          const int &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1909;
  }
  mi_contact mic = *it;
  mic.country_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactCity(const std::string &pub_name,
                                       const std::string &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1910;
  }
  mi_contact mic = *it;
  mic.city_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::UpdateContactConfirmed(const std::string &pub_name,
                                            const char &value) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1911;
  }
  mi_contact mic = *it;
  mic.confirmed_ = value;
  cs_.replace(it, mic);
  return 0;
}

int ContactsHandler::SetLastContactRank(const std::string &pub_name) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1912;
  }
  mi_contact mic = *it;
  mic.rank_++;
  mic.last_contact_ = base::get_epoch_time();
  cs_.replace(it, mic);
  return mic.last_contact_;
}

int ContactsHandler::GetContactInfo(const std::string &pub_name,
                                    mi_contact *mic) {
  contact_set::iterator it = cs_.find(pub_name);
  if (it == cs_.end()) {
#ifdef DEBUG
    printf("Contact(%s) not present in contact list.\n", pub_name.c_str());
#endif
    return -1913;
  }
  *mic = *it;
  return 0;
}

// type:  1  - for most contacted
//        2  - for most recent
//        0  - (default) alphabetical
int ContactsHandler::GetContactList(std::vector<mi_contact> *list,
                                       int type) {
  list->clear();
  switch (type) {
    case 0: typedef contact_set::index<pub_name>::type
                    contact_set_by_pub_name;
            for (contact_set_by_pub_name::iterator it =
                 cs_.get<pub_name>().begin();
                 it != cs_.get<pub_name>().end(); it++) {
              mi_contact mic = *it;
              list->push_back(mic);
            }
            break;
    case 1: typedef contact_set::index<rank>::type
                    contact_set_by_rank;
            for (contact_set_by_rank::iterator it = cs_.get<rank>().begin();
                 it != cs_.get<rank>().end(); it++) {
              mi_contact mic = *it;
              list->push_back(mic);
            }
            break;
    case 2: typedef contact_set::index<last_contact>::type
                    contact_set_by_last_contact;
            for (contact_set_by_last_contact::iterator it =
                 cs_.get<last_contact>().begin();
                 it != cs_.get<last_contact>().end(); it++) {
              mi_contact mic = *it;
              list->push_back(mic);
            }
            break;
  }
  return 0;
}

int ContactsHandler::ClearContacts() {
  cs_.clear();
  return 0;
}

}  // namespace maidsafe
