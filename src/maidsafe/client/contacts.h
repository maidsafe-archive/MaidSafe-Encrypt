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

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/shared_ptr.hpp>
#include <functional>
#include <string>
#include <vector>

#include "maidsafe/utils.h"

namespace maidsafe {

// TODO(Dan#5#): 2009-07-22 - Language and country lists to be decided on and
//                            incorporated to the logic.

class Contact {
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
  Contact();
  explicit Contact(const std::vector<std::string> &attributes);

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

struct mi_contact {
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

  mi_contact() : pub_name_(), pub_key_(), full_name_(), office_phone_(),
                 birthday_(), gender_(), language_(), country_(), city_(),
                 confirmed_(), rank_(), last_contact_() {}

  mi_contact(std::string pub_name, std::string pub_key, std::string full_name,
             std::string office_phone, std::string birthday, char gender,
             int language, int country, std::string city, char confirmed,
             int rank, int last_contact)
             : pub_name_(pub_name), pub_key_(pub_key), full_name_(full_name),
               office_phone_(office_phone), birthday_(birthday),
               gender_(gender), language_(language), country_(country),
               city_(city), confirmed_(confirmed), rank_(rank),
               last_contact_(last_contact) {}
};

/* Tags */
struct pub_name {};
struct rank {};
struct last_contact {};

typedef boost::multi_index::multi_index_container<
  mi_contact,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<pub_name>,
      BOOST_MULTI_INDEX_MEMBER(mi_contact, std::string, pub_name_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<rank>,
      BOOST_MULTI_INDEX_MEMBER(mi_contact, int, rank_), std::greater<int>
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<last_contact>,
      BOOST_MULTI_INDEX_MEMBER(mi_contact, int, last_contact_),
      std::greater<int>
    >
  >
> contact_set;

class ContactsHandler {
 private:
  contact_set cs_;

 public:
  ContactsHandler() : cs_() { }
  int AddContact(const std::string &pub_name,
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
                    const int &last_contact);
  int DeleteContact(const std::string &pub_name);
  int UpdateContact(const mi_contact &mic);
  int UpdateContactKey(const std::string &pub_name,
                          const std::string &value);
  int UpdateContactFullName(const std::string &pub_name,
                               const std::string &value);
  int UpdateContactOfficePhone(const std::string &pub_name,
                                  const std::string &value);
  int UpdateContactBirthday(const std::string &pub_name,
                               const std::string &value);
  int UpdateContactGender(const std::string &pub_name,
                             const char &value);
  int UpdateContactLanguage(const std::string &pub_name,
                               const int &value);
  int UpdateContactCountry(const std::string &pub_name,
                              const int &value);
  int UpdateContactCity(const std::string &pub_name,
                           const std::string &value);
  int UpdateContactConfirmed(const std::string &pub_name,
                                const char &value);
  int SetLastContactRank(const std::string &pub_name);
  int GetContactInfo(const std::string &pub_name, mi_contact *mic);

  // type:  1  - for most contacted
  //        2  - for most recent
  //        0  - (default) alphabetical
  int GetContactList(std::vector<mi_contact> *list,
                        int type = 0);

  int ClearContacts();
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CONTACTS_H_
