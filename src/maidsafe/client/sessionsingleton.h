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

#include <boost/utility.hpp>
#include <boost/thread/once.hpp>
#include <boost/scoped_ptr.hpp>
#include <maidsafe/passport/passport.h>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/client/contacts.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/filesystem/distributed_filesystem.pb.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/maidsafe.h"

namespace maidsafe {

namespace vault {
namespace test {
class RunPDVaults;
class PDVaultTest;
}  // namespace test
}  // namespace vault

namespace test {
class SessionSingletonTest;
class RunPDClient;
class DataAtlasHandlerTest;
class ImHandlerTest;
class MultiImHandlerTest;
class ImMessagingTest;
class CCImMessagingTest;
class LocalStoreManagerTest;
class MaidStoreManagerTest;
class SEHandlerTest;
class SessionSingletonTest_BEH_MAID_SetsGetsAndResetSession_Test;
class SessionSingletonTest_BEH_MAID_SessionName_Test;
class AuthenticationTest_FUNC_MAID_RepeatedSaveSessionBlocking_Test;
class AuthenticationTest_FUNC_MAID_RepeatedSaveSessionCallbacks_Test;
class AuthenticationTest_FUNC_MAID_ChangeUsername_Test;
class AuthenticationTest_FUNC_MAID_ChangePin_Test;
class AuthenticationTest_FUNC_MAID_CreatePublicName_Test;
class AuthenticationTest_FUNC_MAID_NET_RepeatedSaveSessionBlocking_Test;
class AuthenticationTest_FUNC_MAID_NET_RepeatedSaveSessionCallbacks_Test;
class AuthenticationTest_FUNC_MAID_NET_ChangeUsername_Test;
class AuthenticationTest_FUNC_MAID_NET_ChangePin_Test;
class AuthenticationTest_FUNC_MAID_NET_CreatePublicName_Test;
class ImMessagingTest_FUNC_MAID_SendReceiveMessages_Test;
class ImMessagingTest_FUNC_MAID_ReceiveEndPointMsg_Test;
class ImMessagingTest_FUNC_MAID_ReceiveLogOutMsg_Test;
class ImMessagingTest_FUNC_MAID_HandleTwoConverstions_Test;
class ImMessagingTest_FUNC_MAID_NET_SendReceiveMessages_Test;
class ImMessagingTest_FUNC_MAID_NET_ReceiveEndPointMsg_Test;
class ImMessagingTest_FUNC_MAID_NET_ReceiveLogOutMsg_Test;
class ImMessagingTest_FUNC_MAID_NET_HandleTwoConverstions_Test;
class ImHandlerTest_BEH_MAID_Create_ValidateMsg_Test;
class LocalStoreManagerTest_BEH_MAID_DeleteSystemPacketNotOwner_Test;
class LocalStoreManagerTest_BEH_MAID_UpdatePacket_Test;
class LocalStoreManagerTest_BEH_MAID_AddAndGetBufferPacketMessages_Test;
class LocalStoreManagerTest_BEH_MAID_AddRequestBufferPacketMessage_Test;
}  // namespace test

class Authentication;
class ClientUtils;

struct UserDetails {
  UserDetails() : defconlevel(kDefCon3),
                  da_modified(false),
                  username(),
                  pin(),
                  password(),
                  public_username(),
                  session_name(),
                  root_db_key(),
                  self_encrypting(true),
                  authorised_users(),
                  maid_authorised_users(),
                  mounted(0),
                  win_drive('\0'),
                  connection_status(0),
                  vault_ip(),
                  vault_port(0),
                  ep(),
                  pd() {}
  DefConLevels defconlevel;
  bool da_modified;
  std::string username, pin, password, public_username, session_name;
  std::string root_db_key;
  bool self_encrypting;
  std::set<std::string> authorised_users;
  std::set<std::string> maid_authorised_users;
  int mounted;
  char win_drive;
  int connection_status;
  std::string vault_ip;
  boost::uint32_t vault_port;
  EndPoint ep;
  PersonalDetails pd;
};

struct ConnectionDetails {
  EndPoint ep;
  boost::uint16_t transport;
  boost::uint32_t connection_id;
  int status;
  boost::uint32_t init_timestamp;
};

class SessionSingleton {
 public:
  static SessionSingleton* getInstance() {
    boost::call_once(Init, flag_);
    return single_.get();
  }
  bool ResetSession();
  virtual ~SessionSingleton() {}
  void Destroy();

  ///////////////////////////////
  //// User Details Handling ////
  ///////////////////////////////

  // Accessors
  DefConLevels DefConLevel();
  bool DaModified();
  std::string Username();
  std::string Pin();
  std::string Password();
  std::string PublicUsername();
  std::string SessionName();
  std::string RootDbKey();
  bool SelfEncrypting();
  const std::set<std::string> &AuthorisedUsers();
  const std::set<std::string> &MaidAuthorisedUsers();
  int Mounted();
  char WinDrive();
  int ConnectionStatus();
  std::string VaultIP();
  boost::uint32_t VaultPort();
  EndPoint Ep();
  PersonalDetails Pd();

  // Mutators
  bool SetDefConLevel(DefConLevels defconlevel);
  bool SetDaModified(bool da_modified);
  bool SetSessionName(bool clear);
  bool SetRootDbKey(const std::string &root_db_key);
  bool SetSelfEncrypting(bool self_encrypting);
  bool SetAuthorisedUsers(
      const std::set<std::string> &authorised_users);
  bool SetMaidAuthorisedUsers(
      const std::set<std::string> &maid_authorised_users);
  bool SetMounted(int mounted);
  bool SetWinDrive(char win_drive);
  bool SetConnectionStatus(int status);
  bool SetVaultIP(const std::string &vault_ip);
  bool SetVaultPort(const boost::uint32_t &vault_port);
  bool SetEp(const EndPoint &ep);
  bool SetPd(const PersonalDetails &pd);

  ///////////////////////////
  //// Key Ring Handling ////
  ///////////////////////////

  int ParseKeyring(const std::string &serialised_keyring);
  std::string SerialiseKeyring();
  int ProxyMID(std::string *id,
               std::string *public_key,
               std::string *private_key,
               std::string *public_key_signature);
  int MPublicID(std::string *id,
                std::string *public_key,
                std::string *private_key,
                std::string *public_key_signature);

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
                      const std::vector<boost::uint32_t> &share_stats,
                      std::list<ShareParticipants> *participants);
  int DeletePrivateShare(const std::string &value, const int &field);
  int AddContactsToPrivateShare(const std::string &value, const int &field,
                                std::list<ShareParticipants> *participants);
  int DeleteContactsFromPrivateShare(const std::string &value,
                                     const int &field,
                                     std::list<std::string> *participants);
  int TouchShare(const std::string &value, const int &field);
  int GetShareInfo(const std::string &value, const int &field,
                   PrivateShare *ps);
  int GetShareKeys(const std::string &msid,
                   std::string *public_key,
                   std::string *private_key);
  int GetShareList(std::list<private_share> *ps_list,
                   const SortingMode &sm, const ShareFilter &sf);
  int GetFullShareList(const SortingMode &sm, const ShareFilter &sf,
                        std::list<PrivateShare> *ps_list);
  int GetParticipantsList(const std::string &value, const int &field,
                          std::list<share_participant> *sp_list);
  void ClearPrivateShares();

  ///////////////////////////////
  //// Conversation Handling ////
  ///////////////////////////////

  int ConversationList(std::list<std::string> *conversations);
  int AddConversation(const std::string &id);
  int RemoveConversation(const std::string &id);
  int ConversationExits(const std::string &id);
  void ClearConversations();

  ///////////////////////////////
  //// Live Contact Handling ////
  ///////////////////////////////

  typedef std::map<std::string, ConnectionDetails> live_map;
  int AddLiveContact(const std::string &contact,
                     const EndPoint &end_points,
                     int status);
  int LivePublicUsernameList(std::list<std::string> *contacts);
  int LiveContactMap(std::map<std::string, ConnectionDetails> *live_contacts);
  int LiveContactDetails(const std::string &contact,
                         EndPoint *end_points,
                         boost::uint16_t *transport_id,
                         boost::uint32_t *connection_id,
                         int *status,
                         boost::uint32_t *init_timestamp);
  int LiveContactTransportConnection(const std::string &contact,
                                     boost::uint16_t *transport_id,
                                     boost::uint32_t *connection_id);
  int LiveContactStatus(const std::string &contact, int *status);
  int StartLiveConnection(const std::string &contact,
                          boost::uint16_t transport_id,
                          const boost::uint32_t &connection_id);
  int ModifyTransportId(const std::string &contact,
                        boost::uint16_t transport_id);
  int ModifyConnectionId(const std::string &contact,
                         const boost::uint32_t &connection_id);
  int ModifyEndPoint(const std::string &contact, const std::string &ip,
                     const boost::uint16_t &port, int which);
  int ModifyEndPoint(const std::string &contact, const EndPoint end_point);
  int ModifyStatus(const std::string &contact,
                   int status);
  int DeleteLiveContact(const std::string &contact);
  void ClearLiveContacts();

 protected:
  SessionSingleton() : ud_(),
                       passport_(new passport::Passport(kRsaKeySize, 5)),
                       ch_(),
                       psh_(),
                       conversations_(),
                       live_contacts_(),
                       lc_mutex_() {}
  // Following four mutators should only be called by Authentication once
  // associated packets are confirmed as stored.
  bool SetUsername(const std::string &username);
  bool SetPin(const std::string &pin);
  bool SetPassword(const std::string &password);
  bool SetPublicUsername(const std::string &public_username);
  // Creates ANMAID, MAID, PMID.  Also ANMPID & MPID if public_username not "".
  bool CreateTestPackets(const std::string &public_username);
  std::string Id(const passport::PacketType &packet_type,
                 bool confirmed_as_stored);
  std::string PublicKey(const passport::PacketType &packet_type,
                        bool confirmed_as_stored);
  std::string PrivateKey(const passport::PacketType &packet_type,
                         bool confirmed_as_stored);
  std::string PublicKeySignature(const passport::PacketType &packet_type,
                                 bool confirmed_as_stored);

 private:
  friend class Authentication;
  friend class ClientUtils;
  friend class MockSessionSingleton;
  friend class test::SessionSingletonTest;
  friend class test::RunPDClient;
  friend class vault::test::RunPDVaults;
  friend class vault::test::PDVaultTest;
  friend class test::DataAtlasHandlerTest;
  friend class test::ImHandlerTest;
  friend class test::MultiImHandlerTest;
  friend class test::ImMessagingTest;
  friend class test::LocalStoreManagerTest;
  friend class test::MaidStoreManagerTest;
  friend class test::SEHandlerTest;
  friend class test::CCImMessagingTest;
  friend class test::SessionSingletonTest_BEH_MAID_SetsGetsAndResetSession_Test;
  friend class test::SessionSingletonTest_BEH_MAID_SessionName_Test;
  friend class
      test::AuthenticationTest_FUNC_MAID_RepeatedSaveSessionBlocking_Test;
  friend class
      test::AuthenticationTest_FUNC_MAID_RepeatedSaveSessionCallbacks_Test;
  friend class test::AuthenticationTest_FUNC_MAID_ChangeUsername_Test;
  friend class test::AuthenticationTest_FUNC_MAID_ChangePin_Test;
  friend class test::AuthenticationTest_FUNC_MAID_CreatePublicName_Test;
  friend class
      test::AuthenticationTest_FUNC_MAID_NET_RepeatedSaveSessionBlocking_Test;
  friend class
      test::AuthenticationTest_FUNC_MAID_NET_RepeatedSaveSessionCallbacks_Test;
  friend class test::AuthenticationTest_FUNC_MAID_NET_ChangeUsername_Test;
  friend class test::AuthenticationTest_FUNC_MAID_NET_ChangePin_Test;
  friend class test::AuthenticationTest_FUNC_MAID_NET_CreatePublicName_Test;
  friend class test::ImMessagingTest_FUNC_MAID_SendReceiveMessages_Test;
  friend class test::ImMessagingTest_FUNC_MAID_ReceiveEndPointMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_ReceiveLogOutMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_HandleTwoConverstions_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_SendReceiveMessages_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_ReceiveEndPointMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_ReceiveLogOutMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_HandleTwoConverstions_Test;
  friend class test::ImHandlerTest_BEH_MAID_Create_ValidateMsg_Test;
  friend class
      test::LocalStoreManagerTest_BEH_MAID_DeleteSystemPacketNotOwner_Test;
  friend class test::LocalStoreManagerTest_BEH_MAID_UpdatePacket_Test;
  friend class
      test::LocalStoreManagerTest_BEH_MAID_AddAndGetBufferPacketMessages_Test;
  friend class
      test::LocalStoreManagerTest_BEH_MAID_AddRequestBufferPacketMessage_Test;
  SessionSingleton &operator=(const SessionSingleton&);
  SessionSingleton(const SessionSingleton&);
  static void Init() { single_.reset(new SessionSingleton()); }
  int GetKey(const passport::PacketType &packet_type,
             std::string *id,
             std::string *public_key,
             std::string *private_key,
             std::string *public_key_signature);
  static boost::scoped_ptr<SessionSingleton> single_;
  static boost::once_flag flag_;
  UserDetails ud_;
  boost::shared_ptr<passport::Passport> passport_;
  ContactsHandler ch_;
  PrivateShareHandler psh_;
  std::set<std::string> conversations_;
  std::map<std::string, ConnectionDetails> live_contacts_;
  boost::mutex lc_mutex_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_SESSIONSINGLETON_H_
