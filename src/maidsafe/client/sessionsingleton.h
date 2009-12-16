/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton for setting/getting session info
* Version:      1.0
* Created:      2009-01-28-16.56.20
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

#ifndef MAIDSAFE_CLIENT_SESSIONSINGLETON_H_
#define MAIDSAFE_CLIENT_SESSIONSINGLETON_H_

#include <boost/thread/thread.hpp>
#include <maidsafe/crypto.h>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "maidsafe/client/keyatlas.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/privateshares.h"
#include "protobuf/datamaps.pb.h"

namespace maidsafe {

enum DefConLevels {DEFCON1 = 1, DEFCON2, DEFCON3};

struct UserDetails {
  UserDetails() : defconlevel(DEFCON3),
                  da_modified(false),
                  username(""),
                  pin(""),
                  password(""),
                  mid_rid(0),
                  smid_rid(0),
                  session_name(""),
                  root_db_key(""),
                  self_encrypting(true),
                  authorised_users(),
                  maid_authorised_users(),
                  mounted(0),
                  win_drive('\0'),
                  connection_status(0),
                  vault_ip(),
                  vault_port(0) {}
  DefConLevels defconlevel;
  bool da_modified;
  std::string username;
  std::string pin;
  std::string password;
  boost::uint32_t mid_rid;
  boost::uint32_t smid_rid;
  std::string session_name;
  std::string root_db_key;
  bool self_encrypting;
  std::set<std::string> authorised_users;
  std::set<std::string> maid_authorised_users;
  int mounted;
  char win_drive;
  int connection_status;
  std::string vault_ip;
  boost::uint32_t vault_port;
};

class SessionSingleton {
 public:
  bool ResetSession();
  static SessionSingleton* getInstance();
  static void Destroy();

  ///////////////////////////////
  //// User Details Handling ////
  ///////////////////////////////

  // Accessors
  inline DefConLevels DefConLevel() { return ud_.defconlevel; }
  inline bool DaModified() { return ud_.da_modified; }
  inline std::string Username() { return ud_.username; }
  inline std::string Pin() { return ud_.pin; }
  inline std::string Password() { return ud_.password; }
  inline std::string PublicUsername() { return Id(MPID); }
  inline boost::uint32_t MidRid() { return ud_.mid_rid; }
  inline boost::uint32_t SmidRid() { return ud_.smid_rid; }
  inline std::string SessionName() { return ud_.session_name; }
  inline std::string RootDbKey() { return ud_.root_db_key; }
  inline bool SelfEncrypting() { return ud_.self_encrypting; }
  inline std::set<std::string> AuthorisedUsers() {
    return ud_.authorised_users;
  }
  inline std::set<std::string> MaidAuthorisedUsers() {
    return ud_.maid_authorised_users;
  }
  inline int Mounted() { return ud_.mounted; }
  inline char WinDrive() { return ud_.win_drive; }
  inline int ConnectionStatus() { return ud_.connection_status; }
  inline std::string VaultIP() { return ud_.vault_ip; }
  inline boost::uint32_t VaultPort() { return ud_.vault_port; }

  // Mutators
  inline bool SetDefConLevel(DefConLevels defconlevel) {
    ud_.defconlevel = defconlevel;
    return true;
  }
  inline bool SetDaModified(bool da_modified) {
    ud_.da_modified = da_modified;
    return true;
  }
  inline bool SetUsername(const std::string &username) {
    ud_.username = username;
    return true;
  }
  inline bool SetPin(const std::string &pin) {
    ud_.pin = pin;
    return true;
  }
  inline bool SetPassword(const std::string &password) {
    ud_.password = password;
    return true;
  }
  inline bool SetMidRid(const boost::uint32_t &midrid) {
    ud_.mid_rid = midrid;
    return true;
  }
  inline bool SetSmidRid(const boost::uint32_t &smidrid) {
    ud_.smid_rid = smidrid;
    return true;
  }
  inline bool SetSessionName(bool clear) {
    if (clear) {
      ud_.session_name = "";
    } else {
      if (Username() == "" || Pin() == "")
        return false;
      crypto::Crypto c;
      c.set_hash_algorithm(crypto::SHA_1);
      ud_.session_name = c.Hash(Pin()+Username(),
                                "",
                                crypto::STRING_STRING,
                                true);
    }
    return true;
  }
  inline bool SetRootDbKey(const std::string &root_db_key_) {
    ud_.root_db_key = root_db_key_;
    return true;
  }
  inline bool SetSelfEncrypting(bool self_encrypting) {
    ud_.self_encrypting = self_encrypting;
    return true;
  }
  inline bool SetAuthorisedUsers(
      const std::set<std::string> &authorised_users) {
    ud_.authorised_users = authorised_users;
    return true;
  }
  inline bool SetMaidAuthorisedUsers(
      const std::set<std::string> &maid_authorised_users) {
    ud_.maid_authorised_users = maid_authorised_users;
    return true;
  }
  inline bool SetMounted(int mounted) {
    ud_.mounted = mounted;
    return true;
  }
  inline bool SetWinDrive(char win_drive) {
    ud_.win_drive = win_drive;
    return true;
  }
  inline bool SetConnectionStatus(int status) {
    ud_.connection_status = status;
    return true;
  }
  inline bool SetVaultIP(const std::string &vault_ip) {
    ud_.vault_ip = vault_ip;
    return true;
  }
  inline bool SetVaultPort(const boost::uint32_t &vault_port) {
    if ((vault_port > 1023 && vault_port < 65536) || vault_port == 0) {
      ud_.vault_port = vault_port;
      return true;
    } else {
      return false;
    }
  }

  ///////////////////////////
  //// Key Ring Handling ////
  ///////////////////////////

  int LoadKeys(std::list<Key> *keys);
  void GetKeys(std::list<KeyAtlasRow> *keys);
  void SerialisedKeyRing(std::string *ser_kr);
  // If signed_public_key == "", it is set as signature of given public_key
  // using given private_key.
  void AddKey(const PacketType &bpt, const std::string &id,
              const std::string &private_key, const std::string &public_key,
              const std::string &signed_public_key);
  std::string Id(const PacketType &bpt);
  std::string PublicKey(const PacketType &bpt);
  std::string PrivateKey(const PacketType &bpt);
  std::string SignedPublicKey(const PacketType &bpt);

  ///////////////////////////
  //// Contacts Handling ////
  ///////////////////////////

  int LoadContacts(std::list<PublicContact> *contacts);
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
  std::string GetContactPublicKey(const std::string &pub_name);

  // type:  1  - for most contacted
  //        2  - for most recent
  //        0  - (default) alphabetical
  int GetContactList(std::vector<mi_contact> *list,
                     int type = 0);
  int GetPublicUsernameList(std::vector<std::string> *list);
  int ClearContacts();

  ////////////////////////////////
  //// Private Share Handling ////
  ////////////////////////////////

  int LoadShares(std::list<Share> *shares);
  int AddPrivateShare(const std::vector<std::string> &attributes,
                      std::list<ShareParticipants> *participants);
  int DeletePrivateShare(const std::string &value, const int &field);
  int AddContactsToPrivateShare(const std::string &value, const int &field,
                                std::list<ShareParticipants> *participants);
  int DeleteContactsFromPrivateShare(const std::string &value,
                                     const int &field,
                                     std::list<std::string> *participants);
  int GetShareInfo(const std::string &value, const int &field,
                   PrivateShare *ps);
  int GetShareKeys(const std::string &msid,
                   std::string *public_key,
                   std::string *private_key);
  int GetShareList(std::list<maidsafe::private_share> *ps_list,
                   const SortingMode &sm);
  int GetFullShareList(std::list<PrivateShare> *ps_list);
  int GetParticipantsList(const std::string &value, const int &field,
                          std::list<share_participant> *sp_list);
  void ClearPrivateShares();

 private:
  SessionSingleton &operator=(const SessionSingleton&);
  SessionSingleton(const SessionSingleton&);
  static SessionSingleton *single;
  ~SessionSingleton() {}
  UserDetails ud_;
  KeyAtlas ka_;
  ContactsHandler ch_;
  PrivateShareHandler psh_;
  SessionSingleton() : ud_(), ka_(), ch_(), psh_() { ResetSession(); }
};
}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_SESSIONSINGLETON_H_
