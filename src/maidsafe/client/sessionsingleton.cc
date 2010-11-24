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

#include "maidsafe/client/sessionsingleton.h"
#include <boost/tr1/memory.hpp>
#include "maidsafe/common/commonutils.h"

namespace maidsafe {

boost::scoped_ptr<SessionSingleton> SessionSingleton::single_;
boost::once_flag SessionSingleton::flag_ = BOOST_ONCE_INIT;

bool SessionSingleton::ResetSession() {
  ud_.defconlevel = kDefCon3;
  ud_.da_modified = false;
  ud_.username.clear();
  ud_.pin.clear();
  ud_.password.clear();
  ud_.public_username.clear();
  ud_.session_name.clear();
  ud_.root_db_key.clear();
  ud_.self_encrypting = true;
  ud_.authorised_users.clear();
  ud_.maid_authorised_users.clear();
  ud_.mounted = 0;
  ud_.win_drive = '\0';
  ud_.connection_status = 1;
  ud_.ep.Clear();
  ud_.pd.Clear();
  passport_->ClearKeyring();
  ch_.ClearContacts();
  psh_.MI_ClearPrivateShares();
  conversations_.clear();
  live_contacts_.clear();
  return true;
}

void SessionSingleton::Destroy() {
  passport_.reset();
  single_.reset();
  flag_ = BOOST_ONCE_INIT;
}


///////////////////////////////
//// User Details Handling ////
///////////////////////////////

// Accessors
DefConLevels SessionSingleton::DefConLevel() { return ud_.defconlevel; }
bool SessionSingleton::DaModified() { return ud_.da_modified; }
std::string SessionSingleton::Username() { return ud_.username; }
std::string SessionSingleton::Pin() { return ud_.pin; }
std::string SessionSingleton::Password() { return ud_.password; }
std::string SessionSingleton::PublicUsername() { return ud_.public_username; }
std::string SessionSingleton::SessionName() { return ud_.session_name; }
std::string SessionSingleton::RootDbKey() { return ud_.root_db_key; }
bool SessionSingleton::SelfEncrypting() { return ud_.self_encrypting; }
const std::set<std::string> &SessionSingleton::AuthorisedUsers() {
  return ud_.authorised_users;
}
const std::set<std::string> &SessionSingleton::MaidAuthorisedUsers() {
  return ud_.maid_authorised_users;
}
int SessionSingleton::Mounted() { return ud_.mounted; }
char SessionSingleton::WinDrive() { return ud_.win_drive; }
int SessionSingleton::ConnectionStatus() { return ud_.connection_status; }
EndPoint SessionSingleton::Ep() { return ud_.ep; }
PersonalDetails SessionSingleton::Pd() { return ud_.pd; }

// Mutators
bool SessionSingleton::SetDefConLevel(DefConLevels defconlevel) {
  ud_.defconlevel = defconlevel;
  return true;
}
bool SessionSingleton::SetDaModified(bool da_modified) {
  ud_.da_modified = da_modified;
  return true;
}
bool SessionSingleton::SetUsername(const std::string &username) {
  ud_.username = username;
  return true;
}
bool SessionSingleton::SetPin(const std::string &pin) {
  ud_.pin = pin;
  return true;
}
bool SessionSingleton::SetPassword(const std::string &password) {
  ud_.password = password;
  return true;
}
bool SessionSingleton::SetPublicUsername(const std::string &public_username) {
  ud_.public_username = public_username;
  return true;
}
bool SessionSingleton::SetSessionName(bool clear) {
  if (clear) {
    ud_.session_name = "";
  } else {
    if (Username() == "" || Pin() == "")
      return false;
    ud_.session_name = base::EncodeToHex(SHA1String(Pin() + Username()));
  }
  return true;
}
bool SessionSingleton::SetRootDbKey(const std::string &root_db_key) {
  ud_.root_db_key = root_db_key;
  return true;
}
bool SessionSingleton::SetSelfEncrypting(bool self_encrypting) {
  ud_.self_encrypting = self_encrypting;
  return true;
}
bool SessionSingleton::SetAuthorisedUsers(
    const std::set<std::string> &authorised_users) {
  ud_.authorised_users = authorised_users;
  return true;
}
bool SessionSingleton::SetMaidAuthorisedUsers(
    const std::set<std::string> &maid_authorised_users) {
  ud_.maid_authorised_users = maid_authorised_users;
  return true;
}
bool SessionSingleton::SetMounted(int mounted) {
  ud_.mounted = mounted;
  return true;
}
bool SessionSingleton::SetWinDrive(char win_drive) {
  ud_.win_drive = win_drive;
  return true;
}
bool SessionSingleton::SetConnectionStatus(int status) {
  ud_.connection_status = status;
  return true;
}
bool SessionSingleton::SetEp(const EndPoint &ep) {
  ud_.ep = ep;
  return true;
}
bool SessionSingleton::SetPd(const PersonalDetails &pd) {
  ud_.pd = pd;
  return true;
}

/////////////////////////
// Key ring operations //
/////////////////////////

int SessionSingleton::ParseKeyring(const std::string &serialised_keyring) {
  return passport_->ParseKeyring(serialised_keyring);
}

std::string SessionSingleton::SerialiseKeyring() {
  return passport_->SerialiseKeyring();
}

int SessionSingleton::ProxyMID(std::string *id,
                               std::string *public_key,
                               std::string *private_key,
                               std::string *public_key_signature) {
  return GetKey(passport::PMID, id, public_key, private_key,
                public_key_signature);
}

int SessionSingleton::MPublicID(std::string *id,
                                std::string *public_key,
                                std::string *private_key,
                                std::string *public_key_signature) {
  return GetKey(passport::MPID, id, public_key, private_key,
                public_key_signature);
}

int SessionSingleton::GetKey(const passport::PacketType &packet_type,
                             std::string *id,
                             std::string *public_key,
                             std::string *private_key,
                             std::string *public_key_signature) {
  std::tr1::shared_ptr<passport::SignaturePacket> packet(
      std::tr1::static_pointer_cast<passport::SignaturePacket>(
          passport_->GetPacket(packet_type, true)));
  int result(packet ? kSuccess : kGetKeyFailure);
  if (id) {
    if (result == kSuccess)
      *id = packet->name();
    else
      id->clear();
  }
  if (public_key) {
    if (result == kSuccess)
      *public_key = packet->value();
    else
      public_key->clear();
  }
  if (private_key) {
    if (result == kSuccess)
      *private_key = packet->private_key();
    else
      private_key->clear();
  }
  if (public_key_signature) {
    if (result == kSuccess)
      *public_key_signature = packet->public_key_signature();
    else
      public_key_signature->clear();
  }
  return result;
}

bool SessionSingleton::CreateTestPackets(const std::string &public_username) {
  passport_->Init();
  std::tr1::shared_ptr<passport::SignaturePacket>
      pkt(new passport::SignaturePacket);
  if (passport_->InitialiseSignaturePacket(passport::ANMAID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (passport_->InitialiseSignaturePacket(passport::MAID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (passport_->InitialiseSignaturePacket(passport::PMID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (public_username.empty())
    return true;
  if (passport_->InitialiseSignaturePacket(passport::ANMPID, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  if (passport_->InitialiseMpid(public_username, pkt) != kSuccess)
    return false;
  if (passport_->ConfirmSignaturePacket(pkt) != kSuccess)
    return false;
  SetPublicUsername(public_username);
    return true;
}

std::string SessionSingleton::Id(const passport::PacketType &packet_type,
                                 bool confirmed_as_stored) {
  return passport_->SignaturePacketName(packet_type, confirmed_as_stored);
}

std::string SessionSingleton::PublicKey(const passport::PacketType &packet_type,
                                        bool confirmed_as_stored) {
  return passport_->SignaturePacketPublicKey(packet_type, confirmed_as_stored);
}

std::string SessionSingleton::PrivateKey(
    const passport::PacketType &packet_type,
    bool confirmed_as_stored) {
  return passport_->SignaturePacketPrivateKey(packet_type, confirmed_as_stored);
}

std::string SessionSingleton::PublicKeySignature(
    const passport::PacketType &packet_type,
    bool confirmed_as_stored) {
  return passport_->SignaturePacketPublicKeySignature(packet_type,
                                                      confirmed_as_stored);
}

////////////////////////
// Contact operations //
////////////////////////

int SessionSingleton::LoadContacts(std::list<PublicContact> *contacts) {
  int n = 0;
  while (!contacts->empty()) {
    PublicContact pc = contacts->front();
    n += AddContact(pc.pub_name(), pc.pub_key(), pc.full_name(),
                    pc.office_phone(), pc.birthday(), pc.gender().at(0),
                    pc.language(), pc.country(), pc.city(),
                    pc.confirmed().at(0), pc.rank(), pc.last_contact());
    contacts->pop_front();
  }
  return n;
}

int SessionSingleton::AddContact(const std::string &pub_name,
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
  return ch_.AddContact(pub_name, pub_key, full_name, office_phone, birthday,
                           gender, language, country, city, confirmed, rank,
                           last_contact);
}
int SessionSingleton::DeleteContact(const std::string &pub_name) {
  return ch_.DeleteContact(pub_name);
}
int SessionSingleton::UpdateContact(const mi_contact &mic) {
  return ch_.UpdateContact(mic);
}
int SessionSingleton::UpdateContactKey(const std::string &pub_name,
                                       const std::string &value) {
  return ch_.UpdateContactKey(pub_name, value);
}
int SessionSingleton::UpdateContactFullName(const std::string &pub_name,
                                            const std::string &value) {
  return ch_.UpdateContactFullName(pub_name, value);
}
int SessionSingleton::UpdateContactOfficePhone(const std::string &pub_name,
                                               const std::string &value) {
  return ch_.UpdateContactOfficePhone(pub_name, value);
}
int SessionSingleton::UpdateContactBirthday(const std::string &pub_name,
                                            const std::string &value) {
  return ch_.UpdateContactBirthday(pub_name, value);
}
int SessionSingleton::UpdateContactGender(const std::string &pub_name,
                                          const char &value) {
  return ch_.UpdateContactGender(pub_name, value);
}
int SessionSingleton::UpdateContactLanguage(const std::string &pub_name,
                                            const int &value) {
  return ch_.UpdateContactLanguage(pub_name, value);
}
int SessionSingleton::UpdateContactCountry(const std::string &pub_name,
                                           const int &value) {
  return ch_.UpdateContactCountry(pub_name, value);
}
int SessionSingleton::UpdateContactCity(const std::string &pub_name,
                                        const std::string &value) {
  return ch_.UpdateContactCity(pub_name, value);
}
int SessionSingleton::UpdateContactConfirmed(const std::string &pub_name,
                                             const char &value) {
  return ch_.UpdateContactConfirmed(pub_name, value);
}
int SessionSingleton::SetLastContactRank(const std::string &pub_name) {
  return ch_.SetLastContactRank(pub_name);
}
int SessionSingleton::GetContactInfo(const std::string &pub_name,
                                     mi_contact *mic) {
  return ch_.GetContactInfo(pub_name, mic);
}
std::string SessionSingleton::GetContactPublicKey(const std::string &pub_name) {
  mi_contact mic;
  if (ch_.GetContactInfo(pub_name, &mic) != 0)
    return "";
  return mic.pub_key_;
}

// type:  1  - for most contacted
//        2  - for most recent
//        0  - (default) alphabetical
int SessionSingleton::GetContactList(std::vector<mi_contact> *list,
                                     int type) {
  return ch_.GetContactList(list, type);
}
int SessionSingleton::GetPublicUsernameList(std::vector<std::string> *list) {
  list->clear();
  std::vector<mi_contact> mic_list;
  if (ch_.GetContactList(&mic_list, 0) != 0)
    return kContactListFailure;
  for (size_t n = 0; n < mic_list.size(); ++n)
    list->push_back(mic_list[n].pub_name_);
  return 0;
}
int SessionSingleton::ClearContacts() {
  return ch_.ClearContacts();
}

//////////////////////////////
// Private Share operations //
//////////////////////////////

int SessionSingleton::LoadShares(std::list<Share> *shares) {
  int a = 0;
  while (!shares->empty()) {
    Share sh = shares->front();
    std::list<ShareParticipants> sp;
    for (int n = 0; n < sh.participants_size(); n++) {
      sp.push_back(ShareParticipants(sh.participants(n).public_name(),
                                     sh.participants(n).public_name_pub_key(),
                                     sh.participants(n).role().at(0)));
    }
    std::vector<std::string> attributes;
    attributes.push_back(sh.name());
    attributes.push_back(sh.msid());
    attributes.push_back(sh.msid_pub_key());
    if (sh.has_msid_pri_key())
      attributes.push_back(sh.msid_pri_key());
    else
      attributes.push_back("");
    std::vector<boost::uint32_t> share_stats;
    share_stats.push_back(sh.rank());
    share_stats.push_back(sh.last_view());
    shares->pop_front();
    a += AddPrivateShare(attributes, share_stats, &sp);
  }
  return a;
}
int SessionSingleton::AddPrivateShare(
    const std::vector<std::string> &attributes,
    const std::vector<boost::uint32_t> &share_stats,
    std::list<ShareParticipants> *participants) {
  return psh_.MI_AddPrivateShare(attributes, share_stats, participants);
}
int SessionSingleton::DeletePrivateShare(const std::string &value,
    const int &field) {
  return psh_.MI_DeletePrivateShare(value, field);
}
int SessionSingleton::AddContactsToPrivateShare(const std::string &value,
    const int &field, std::list<ShareParticipants> *participants) {
  return psh_.MI_AddContactsToPrivateShare(value, field, participants);
}
int SessionSingleton::DeleteContactsFromPrivateShare(const std::string &value,
    const int &field, std::list<std::string> *participants) {
  return psh_.MI_DeleteContactsFromPrivateShare(value, field, participants);
}
int SessionSingleton::TouchShare(const std::string &value, const int &field) {
  return psh_.MI_TouchShare(value, field);
}
int SessionSingleton::GetShareInfo(const std::string &value, const int &field,
    PrivateShare *ps) {
  return psh_.MI_GetShareInfo(value, field, ps);
}
int SessionSingleton::GetShareKeys(const std::string &msid,
                                   std::string *public_key,
                                   std::string *private_key) {
  PrivateShare ps;
  if (GetShareInfo(msid, 1, &ps) != 0) {
    printf("Pelation en SS::GetShareKeys\n");
    *public_key = "";
    *private_key = "";
    return -1;
  }
  *public_key = ps.MsidPubKey();
  *private_key = ps.MsidPriKey();
  return 0;
}
int SessionSingleton::GetShareList(std::list<private_share> *ps_list,
                                   const SortingMode &sm,
                                   const ShareFilter &sf) {
  return psh_.MI_GetShareList(ps_list, sm, sf);
}
int SessionSingleton::GetFullShareList(const SortingMode &sm,
                                       const ShareFilter &sf,
                                       std::list<PrivateShare> *ps_list) {
  return psh_.MI_GetFullShareList(sm, sf, ps_list);
}
int SessionSingleton::GetParticipantsList(const std::string &value,
    const int &field, std::list<share_participant> *sp_list) {
  return psh_.MI_GetParticipantsList(value, field, sp_list);
}
void SessionSingleton::ClearPrivateShares() {
  return psh_.MI_ClearPrivateShares();
}

///////////////////////////////
//// Conversation Handling ////
///////////////////////////////

int SessionSingleton::ConversationList(std::list<std::string> *conversations) {
  conversations->clear();
  *conversations = std::list<std::string>(conversations_.begin(),
                                          conversations_.end());
  return 0;
}
int SessionSingleton::AddConversation(const std::string &id) {
  if (id.empty())
    return kEmptyConversationId;

  std::pair<std::set<std::string>::iterator, bool> ret;
  ret = conversations_.insert(id);

  if (!ret.second)
    return kExistingConversation;

  return 0;
}
int SessionSingleton::RemoveConversation(const std::string &id) {
  if (id.empty())
    return kEmptyConversationId;

  size_t t = conversations_.erase(id);
  if (t == 0)
    return kNonExistentConversation;

  return 0;
}
int SessionSingleton::ConversationExits(const std::string &id) {
  if (id.empty())
    return kEmptyConversationId;

  std::set<std::string>::iterator it = conversations_.find(id);
  if (it == conversations_.end())
    return kNonExistentConversation;

  return 0;
}
void SessionSingleton::ClearConversations() {
  conversations_.clear();
}

///////////////////////////////
//// Live Contact Handling ////
///////////////////////////////

int SessionSingleton::AddLiveContact(const std::string &contact,
                                     const EndPoint &end_points,
                                     int status) {
  ConnectionDetails cd;
  cd.ep = end_points;
  cd.status = status;
  cd.transport = 0;
  cd.connection_id = 0;
  cd.init_timestamp = 0;

  std::pair<live_map::iterator, bool> p;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    p = live_contacts_.insert(
        std::pair<std::string, ConnectionDetails>(contact, cd));
  }
  if (!p.second)
    return kAddLiveContactFailure;

  return kSuccess;
}

int SessionSingleton::LivePublicUsernameList(std::list<std::string> *contacts) {
  contacts->clear();
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it;
    for (it = live_contacts_.begin(); it != live_contacts_.end(); ++it)
      contacts->push_back(it->first);
  }
  return kSuccess;
}

int SessionSingleton::LiveContactMap(
    std::map<std::string, ConnectionDetails> *live_contacts) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    *live_contacts = live_contacts_;
  }
  return kSuccess;
}

int SessionSingleton::LiveContactDetails(const std::string &contact,
                                         EndPoint *end_points,
                                         boost::uint16_t *transport_id,
                                         boost::uint32_t *connection_id,
                                         int *status,
                                         boost::uint32_t *init_timestamp) {
  end_points->Clear();
  *transport_id = 0;
  *connection_id = 0;
  *status = 0;
  *init_timestamp = 0;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    *end_points = it->second.ep;
    *transport_id = it->second.transport;
    *connection_id = it->second.connection_id;
    *status = it->second.status;
    *init_timestamp = it->second.init_timestamp;
  }
  return kSuccess;
}

int SessionSingleton::LiveContactTransportConnection(
    const std::string &contact,
    boost::uint16_t *transport_id,
    boost::uint32_t *connection_id) {
  *transport_id = 0;
  *connection_id = 0;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    *transport_id = it->second.transport;
    *connection_id = it->second.connection_id;
  }
  return kSuccess;
}

int SessionSingleton::LiveContactStatus(const std::string &contact,
                                        int *status) {
  *status = -1;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    *status = it->second.status;
  }
  return kSuccess;
}

int SessionSingleton::StartLiveConnection(const std::string &contact,
                                          boost::uint16_t transport_id,
                                          const boost::uint32_t &conn_id) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.transport = transport_id;
    it->second.connection_id = conn_id;
    it->second.init_timestamp = base::GetEpochTime();
  }
  return kSuccess;
}

int SessionSingleton::ModifyTransportId(const std::string &contact,
                                        boost::uint16_t transport_id) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.transport = transport_id;
  }
  return kSuccess;
}

int SessionSingleton::ModifyConnectionId(const std::string &contact,
                                         const boost::uint32_t &connection_id) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.connection_id = connection_id;
  }
  return kSuccess;
}

int SessionSingleton::ModifyEndPoint(const std::string &contact,
                                     const std::string &ip,
                                     const boost::uint16_t &port,
                                     int which) {
  if (which < 0 || which > 2)
    return kLiveContactNoEp;
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;

    if (which >= it->second.ep.ip_size())
      return kLiveContactNoEp;
    it->second.ep.set_ip(which, ip);
    it->second.ep.set_port(which, port);
  }
  return kSuccess;
}

int SessionSingleton::ModifyEndPoint(const std::string &contact,
                                     const EndPoint end_point) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.ep = end_point;
  }
  return kSuccess;
}

int SessionSingleton::ModifyStatus(const std::string &contact, int status) {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_map::iterator it = live_contacts_.find(contact);
    if (it == live_contacts_.end())
      return kLiveContactNotFound;
    it->second.status = status;
  }
  return kSuccess;
}

int SessionSingleton::DeleteLiveContact(const std::string &contact) {
  size_t n(0);
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    n = live_contacts_.erase(contact);
  }
  return n;
}

void SessionSingleton::ClearLiveContacts() {
  {
    boost::mutex::scoped_lock loch_awe(lc_mutex_);
    live_contacts_.clear();
  }
}

}  // namespace maidsafe


