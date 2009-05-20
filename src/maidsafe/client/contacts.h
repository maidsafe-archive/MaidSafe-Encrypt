/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe contacts
* Version:      1.0
* Created:      2009-01-28-23.19.56
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

#ifndef MAIDSAFE_CLIENT_CONTACTS_H_
#define MAIDSAFE_CLIENT_CONTACTS_H_

#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>

#include "maidsafe/cppsqlite3.h"
#include "maidsafe/utils.h"

//  Return codes:
//   0: Success
//  -1: Can't connect to share contacts DB
//  -2: Didn't delete pointer db_
//  -3: Add contact failed
//  -4: Delete contact failed
//  -5: Update contact failed
//  -6: Language not found
//  -7: Language id not found
//  -8: Country not found
//  -9: Country id not found
//  -10: Error getting list
//  -11: Error updating last contact and rank

namespace maidsafe {

class Languages {
 private:
  int language_id_;
  std::string language_;

 public:
  int FindLanguage(const int &id, std::string &language);
  int FindLanguageId(const std::string &language, int &id);
};

class Countries {
 private:
  int country_id_;
  std::string country_;

 public:
  int FindCountry(const int &id, std::string &country);
  int FindCountryId(const std::string &country, int &id);
};

class Contacts {
 private:
  std::string pub_name_;
  std::string pub_key_;
  std::string full_name_;
  std::string office_phone_;
  std::string birthday_;
  char gender_;
  int language_;
  int country_;
  std::string city_;
  char confirmed_;
  int rank_;
  int last_contact_;

 public:
  //  Constructors
  Contacts();
  explicit Contacts(const std::vector<std::string> &attributes);

  //  Getters
  inline std::string PublicName() { return pub_name_; }
  inline std::string PublicKey() { return pub_key_; }
  inline std::string FullName() { return full_name_; }
  inline std::string OfficePhone() { return office_phone_; }
  inline std::string Birthday() { return birthday_; }
  inline char Gender() { return gender_; }
  inline int Language() { return language_; }
  inline int Country() { return country_; }
  inline std::string City() { return city_; }
  inline char Confirmed() { return confirmed_; }
  inline int Rank() { return rank_; }
  inline int LastContact() { return last_contact_; }

  // Setters
  inline bool SetPublicName(std::string pub_name) {
    pub_name_ = pub_name;
    return true;
  }
  inline bool SetPublicKey(std::string pub_key) {
    pub_key_ = pub_key;
    return true;
  }
  inline bool SetFullName(std::string full_name) {
    full_name_ = full_name;
    return true;
  }
  inline bool SetOfficePhone(std::string office_phone) {
    office_phone_ = office_phone;
    return true;
  }
  inline bool SetBirthday(std::string birthday) {
    birthday_ = birthday;
    return true;
  }
  inline bool SetGender(char gender) {
    gender_ = gender;
    return true;
  }
  inline bool SetLanguage(int language) {
    language_ = language;
    return true;
  }
  inline bool SetCountry(int country) {
    country_ = country;
    return true;
  }
  inline bool SetCity(std::string city) {
    city_ = city;
    return true;
  }
  inline bool SetConfirmed(char confirmed) {
    confirmed_ = confirmed;
    return true;
  }
  inline bool SetRank(int rank) {
    rank_ = rank;
    return true;
  }
  inline bool SetLastContact(int last_contact) {
    last_contact_ = last_contact;
    return true;
  }
};

class ContactsHandler {
 private:
  boost::shared_ptr<CppSQLite3DB> db_;
  int Connect(const std::string &dbName);
  int Close();

 public:
  ContactsHandler() : db_() { }
  int CreateContactDB(const std::string &dbName);
  int AddContact(const std::string &dbName, Contacts &sc);
  int DeleteContact(const std::string &dbName, Contacts &sc);
  int UpdateContact(const std::string &dbName, Contacts &sc);
  int SetLastContactRank(const std::string &dbName, Contacts &sc);
  // pub_name: if a certain public name is needed. can be used for the search
  //           with like=true, since the query is done with pub_name like
  //           %pub_name% in SQL.
  // type:     use 1 for most contacted, use 2 for most recent, 0 (default)
  //           gets all.
  int GetContactList(const std::string &dbName,
                     std::vector<Contacts> &list,
                     const std::string &pub_name,
                     bool like = false,
                     int type = 0);
  // Message handlers
  int HandleAddRequest();
  int HandleAddResponse();
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CONTACTS_H_
