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
#include "protobuf/datamaps.pb.h"

namespace maidsafe {

SessionSingleton* SessionSingleton::single = 0;
boost::mutex ss_mutex;

SessionSingleton::SessionSingleton()
    : ud_(), ka_(), ch_(), psh_(), conversations_() {
  ResetSession();
}

SessionSingleton *SessionSingleton::getInstance() {
  if (single == 0) {
    boost::mutex::scoped_lock lock(ss_mutex);
    if (single == 0)
      single = new SessionSingleton();
  }
  return single;
}

void SessionSingleton::Destroy() {
  delete single;
  single = 0;
}

bool SessionSingleton::ResetSession() {
  SetDaModified(false);
  SetDefConLevel(kDefCon3);
  SetUsername("");
  SetPin("");
  SetPassword("");
  SetMidRid(0);
  SetSmidRid(0);
  SetTmidContent("");
  SetSmidTmidContent("");
  SetSessionName(true);
  SetRootDbKey("");
  std::set<std::string> empty_set;
  SetAuthorisedUsers(empty_set);
  SetMaidAuthorisedUsers(empty_set);
  SetMounted(0);
  SetWinDrive('\0');
  SetConnectionStatus(1);
  SetVaultIP("");
  SetVaultPort(0);
  EndPoint ep;
  ep.set_ip("127.0.0.1");
  ep.set_port(12700);
  SetEp(ep);
  PersonalDetails pd;
  SetPd(pd);
  ka_.ClearKeyRing();
  ch_.ClearContacts();
  psh_.MI_ClearPrivateShares();
  conversations_.clear();
  return true;
}

/////////////////////////
// Key ring operations //
/////////////////////////

int SessionSingleton::LoadKeys(std::list<Key> *keys) {
  if (keys->empty())
    return kLoadKeysFailure;

  int n = 0;
  while (!keys->empty()) {
    Key k = keys->front();
    keys->pop_front();
    AddKey(k.type(), k.id(), k.private_key(), k.public_key(),
        k.public_key_signature());
    ++n;
  }

  return n;
}

void SessionSingleton::GetKeys(std::list<KeyAtlasRow> *keys) {
  keys->clear();
  ka_.GetKeyRing(keys);
}

void SessionSingleton::SerialisedKeyRing(std::string *ser_kr) {
  DataAtlas da;
  std::list<KeyAtlasRow> keys;
  GetKeys(&keys);
  while (!keys.empty()) {
    KeyAtlasRow kar = keys.front();
    Key *k = da.add_keys();
    k->set_type(PacketType(kar.type_));
    k->set_id(kar.id_);
    k->set_private_key(kar.private_key_);
    k->set_public_key(kar.public_key_);
    k->set_public_key_signature(kar.signed_public_key_);
    keys.pop_front();
  }
  da.SerializeToString(ser_kr);
}

int SessionSingleton::AddKey(const PacketType &bpt,
                             const std::string &id,
                             const std::string &private_key,
                             const std::string &public_key,
                             const std::string &signed_public_key) {
  return ka_.AddKey(bpt, id, private_key, public_key, signed_public_key);
}

int SessionSingleton::RemoveKey(const PacketType &bpt) {
  return ka_.RemoveKey(bpt);
}

std::string SessionSingleton::Id(const PacketType &bpt) {
  return ka_.PackageID(bpt);
}

std::string SessionSingleton::PublicKey(const PacketType &bpt) {
  return ka_.PublicKey(bpt);
}

std::string SessionSingleton::PrivateKey(const PacketType &bpt) {
  return ka_.PrivateKey(bpt);
}

std::string SessionSingleton::SignedPublicKey(const PacketType &bpt) {
  return ka_.SignedPublicKey(bpt);
}

unsigned int SessionSingleton::KeyRingSize() {
  return ka_.KeyRingSize();
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
std::string SessionSingleton::GetContactPublicKey(
    const std::string &pub_name) {
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
int SessionSingleton::GetShareList(
    std::list<maidsafe::private_share> *ps_list,
    const SortingMode &sm, const ShareFilter &sf) {
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

}  // namespace maidsafe


