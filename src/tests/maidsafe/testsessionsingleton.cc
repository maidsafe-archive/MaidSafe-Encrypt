/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Unit tests for SessionSingleton
* Version:      1.0
* Created:      2009-07-23
* Revision:     none
* Compiler:     gcc
* Author:       Team Maidsafe
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

#include <gtest/gtest.h>
#include <maidsafe/crypto.h>

#include "maidsafe/client/sessionsingleton.h"

namespace maidsafe {

class SessionSingletonTest : public testing::Test {
 public:
  SessionSingletonTest() : ss_() {}

 protected:
  void SetUp() {
    ss_ = SessionSingleton::getInstance();
    ss_->ResetSession();
  }
  void TearDown() {
    ss_->ResetSession();
  }
  SessionSingleton *ss_;

 private:
  explicit SessionSingletonTest(const maidsafe::SessionSingletonTest&);
  SessionSingletonTest &operator=(const maidsafe::SessionSingletonTest&);
};

TEST_F(SessionSingletonTest, BEH_MAID_SetsGetsAndResetSession) {
  // Check session is clean originally
  ASSERT_FALSE(ss_->DaModified());
  ASSERT_EQ(DEFCON3, ss_->DefConLevel());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->MidRid());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->SmidRid());
  ASSERT_EQ("", ss_->SessionName());
  ASSERT_EQ("", ss_->RootDbKey());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->AuthorisedUsers().size());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->MaidAuthorisedUsers().size());
  ASSERT_EQ(0, ss_->Mounted());
  ASSERT_EQ('\0', ss_->WinDrive());
  std::list<KeyAtlasRow> keys;
  ss_->GetKeys(&keys);
  ASSERT_EQ(static_cast<unsigned int>(0), keys.size());
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(static_cast<unsigned int>(0), list.size());
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->GetFullShareList(&ps_list));
  ASSERT_EQ(static_cast<unsigned int>(0), ps_list.size());

  // Modify session
  ASSERT_TRUE(ss_->SetDaModified(true));
  ASSERT_TRUE(ss_->SetDefConLevel(DEFCON1));
  ASSERT_TRUE(ss_->SetUsername("aaa"));
  ASSERT_TRUE(ss_->SetPin("bbb"));
  ASSERT_TRUE(ss_->SetPassword("ccc"));
  ASSERT_TRUE(ss_->SetMidRid(22));
  ASSERT_TRUE(ss_->SetSmidRid(7));
  ASSERT_TRUE(ss_->SetSessionName(false));
  ASSERT_TRUE(ss_->SetRootDbKey("ddd"));
  std::set<std::string> non_empty_set;
  non_empty_set.insert("eee");
  ASSERT_TRUE(ss_->SetAuthorisedUsers(non_empty_set));
  non_empty_set.insert("fff");
  ASSERT_TRUE(ss_->SetMaidAuthorisedUsers(non_empty_set));
  ASSERT_TRUE(ss_->SetMounted(1));
  ASSERT_TRUE(ss_->SetWinDrive('N'));
  ss_->AddKey(ANMID, "id", "pri_key", "pub_key");
  ASSERT_EQ(0, ss_->AddContact("pub_name", "pub_key", "full_name",
            "office_phone", "birthday", 'M', 18, 6, "city", 'C', 0, 0));
  std::vector<std::string> attributes;
  attributes.push_back("name");
  attributes.push_back("msid");
  attributes.push_back("msid_pub_key");
  attributes.push_back("msid_pri_key");
  std::list<ShareParticipants> participants;
  participants.push_back(ShareParticipants("id", "id_pub_key", 'A'));
  ASSERT_EQ(0, ss_->AddPrivateShare(attributes, &participants));

  // Verify modifications
  ASSERT_TRUE(ss_->DaModified());
  ASSERT_EQ(DEFCON1, ss_->DefConLevel());
  ASSERT_EQ("aaa", ss_->Username());
  ASSERT_EQ("bbb", ss_->Pin());
  ASSERT_EQ("ccc", ss_->Password());
  ASSERT_EQ(static_cast<unsigned int>(22), ss_->MidRid());
  ASSERT_EQ(static_cast<unsigned int>(7), ss_->SmidRid());
  ASSERT_NE("", ss_->SessionName());
  ASSERT_EQ("ddd", ss_->RootDbKey());
  ASSERT_EQ(static_cast<unsigned int>(1), ss_->AuthorisedUsers().size());
  std::set<std::string>::iterator it = ss_->AuthorisedUsers().find("eee");
  ASSERT_FALSE(ss_->AuthorisedUsers().end() == it);
  ASSERT_EQ(static_cast<unsigned int>(2), ss_->MaidAuthorisedUsers().size());
  it = ss_->MaidAuthorisedUsers().find("eee");
  ASSERT_FALSE(ss_->MaidAuthorisedUsers().end() == it);
  it = ss_->MaidAuthorisedUsers().find("fff");
  ASSERT_FALSE(ss_->MaidAuthorisedUsers().end() == it);
  ASSERT_EQ(1, ss_->Mounted());
  ASSERT_EQ('N', ss_->WinDrive());
  ss_->GetKeys(&keys);
  ASSERT_EQ(static_cast<unsigned int>(1), keys.size());
  ASSERT_EQ(ANMID, keys.front().type_);
  ASSERT_EQ("id", keys.front().id_);
  ASSERT_EQ("pri_key", keys.front().private_key_);
  ASSERT_EQ("pub_key", keys.front().public_key_);
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(static_cast<unsigned int>(1), list.size());
  ASSERT_EQ("pub_name", list[0].pub_name_);
  ASSERT_EQ("pub_key", list[0].pub_key_);
  ASSERT_EQ("full_name", list[0].full_name_);
  ASSERT_EQ("office_phone", list[0].office_phone_);
  ASSERT_EQ("birthday", list[0].birthday_);
  ASSERT_EQ('M', list[0].gender_);
  ASSERT_EQ(18, list[0].language_);
  ASSERT_EQ(6, list[0].country_);
  ASSERT_EQ("city", list[0].city_);
  ASSERT_EQ('C', list[0].confirmed_);
  ASSERT_EQ(0, list[0].rank_);
  ASSERT_NE(0, list[0].last_contact_);
  ASSERT_EQ(0, ss_->GetFullShareList(&ps_list));
  ASSERT_EQ(static_cast<unsigned int>(1), ps_list.size());
  ASSERT_EQ("name", ps_list.front().Name());
  ASSERT_EQ("msid", ps_list.front().Msid());
  ASSERT_EQ("msid_pub_key", ps_list.front().MsidPubKey());
  ASSERT_EQ("msid_pri_key", ps_list.front().MsidPriKey());
  std::list<ShareParticipants> sp_list = ps_list.front().Participants();
  ASSERT_EQ(static_cast<unsigned int>(1), sp_list.size());
  ASSERT_EQ("id", sp_list.front().id);
  ASSERT_EQ("id_pub_key", sp_list.front().public_key);
  ASSERT_EQ('A', sp_list.front().role);

  // Resetting the session
  ASSERT_TRUE(ss_->ResetSession());

  // Check session is clean again
  ASSERT_FALSE(ss_->DaModified());
  ASSERT_EQ(DEFCON3, ss_->DefConLevel());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->MidRid());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->SmidRid());
  ASSERT_EQ("", ss_->SessionName());
  ASSERT_EQ("", ss_->RootDbKey());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->AuthorisedUsers().size());
  ASSERT_EQ(static_cast<unsigned int>(0), ss_->MaidAuthorisedUsers().size());
  ASSERT_EQ(0, ss_->Mounted());
  ASSERT_EQ('\0', ss_->WinDrive());
  ss_->GetKeys(&keys);
  ASSERT_EQ(static_cast<unsigned int>(0), keys.size());
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(static_cast<unsigned int>(0), list.size());
  ASSERT_EQ(0, ss_->GetFullShareList(&ps_list));
  ASSERT_EQ(static_cast<unsigned int>(0), ps_list.size());
}

TEST_F(SessionSingletonTest, BEH_MAID_PublicUsername) {
  ASSERT_EQ("", ss_->PublicUsername());
  ASSERT_EQ("", ss_->Id(MPID));
  ss_->AddKey(MPID, "Dan Schmidt", "pri_key", "pub_key");
  ASSERT_EQ("Dan Schmidt", ss_->PublicUsername());
  ASSERT_EQ("Dan Schmidt", ss_->Id(MPID));
}

TEST_F(SessionSingletonTest, BEH_MAID_SessionName) {
  // Check session is empty
  ASSERT_EQ("", ss_->SessionName());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());

  // Check username and pin are needed
  ASSERT_FALSE(ss_->SetSessionName(false));
  ASSERT_EQ("", ss_->SessionName());

  crypto::Crypto c;
  c.set_hash_algorithm(crypto::SHA_1);
  std::string username("user1");
  std::string pin("1234");
  std::string session_name = c.Hash(pin + username, "",
                             crypto::STRING_STRING, true);

  // Set the session values
  ASSERT_TRUE(ss_->SetUsername(username));
  ASSERT_TRUE(ss_->SetPin(pin));
  ASSERT_TRUE(ss_->SetSessionName(false));

  // Check session name
  ASSERT_EQ(session_name, ss_->SessionName());

  // Reset value and check empty again
  ASSERT_TRUE(ss_->SetSessionName(true));
  ASSERT_EQ("", ss_->SessionName());
}

TEST_F(SessionSingletonTest, BEH_MAID_SessionKeyRingIO) {
  std::string pub_keys[7];
  std::string pri_keys[7];
  DataAtlas da;
  for (int n = 0; n < 7; ++n) {
    crypto::RsaKeyPair rskp;
    rskp.GenerateKeys(4096);
    pri_keys[n] = rskp.private_key();
    pub_keys[n] = rskp.public_key();
    Key *k = da.add_keys();
    k->set_type(PacketType(n));
    k->set_id("id" + base::itos(n));
    k->set_private_key(pri_keys[n]);
    k->set_public_key(pub_keys[n]);
    ss_->AddKey(PacketType(n), "id" + base::itos(n),
                pri_keys[n], pub_keys[n]);
  }
  // get signed public key
  for (int i = 0; i < 7; i++) {
    std::string public_key = pub_keys[i];
    std::string private_key = pri_keys[i];
    crypto::Crypto co;
    ASSERT_TRUE(co.AsymCheckSig(public_key, ss_->SignedPublicKey(PacketType(i)),
                public_key, crypto::STRING_STRING));
  }

  std::string ser_da;
  da.SerializeToString(&ser_da);

  std::list<KeyAtlasRow> keys;
  ss_->GetKeys(&keys);
  ASSERT_EQ(static_cast<unsigned int>(7), keys.size());
  int a = 0;
  while (!keys.empty()) {
    ASSERT_EQ(a, keys.front().type_);
    ASSERT_EQ("id" + base::itos(a), keys.front().id_);
    ASSERT_EQ(pri_keys[a], keys.front().private_key_);
    ASSERT_EQ(pub_keys[a], keys.front().public_key_);
    keys.pop_front();
    ++a;
  }

  std::string ser_kr;
  ss_->SerialisedKeyRing(&ser_kr);
  ASSERT_EQ(ser_da, ser_kr);
}

TEST_F(SessionSingletonTest, BEH_MAID_SessionContactsIO) {
  // Add contacts to the session
  for (int n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + base::itos(n),
              "pub_key_" + base::itos(n), "full_name_" + base::itos(n),
              "office_phone_" + base::itos(n), "birthday_" + base::itos(n),
              'M', n, n, "city_" + base::itos(n), 'C', 0, 0));
  }

  // Check contacts are in session
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(static_cast<unsigned int>(10), list.size());

  // Move contacts to a DA
  DataAtlas da;
  for (unsigned int a = 0; a < list.size(); ++a) {
    PublicContact *pc = da.add_contacts();
    pc->set_pub_name(list[a].pub_name_);
    pc->set_pub_key(list[a].pub_key_);
    pc->set_full_name(list[a].full_name_);
    pc->set_office_phone(list[a].office_phone_);
    pc->set_birthday(list[a].birthday_);
    std::string g(1, list[a].gender_);
    pc->set_gender(g);
    pc->set_language(list[a].language_);
    pc->set_country(list[a].country_);
    pc->set_city(list[a].city_);
    std::string c(1, list[a].confirmed_);
    pc->set_confirmed(c);
    pc->set_rank(list[a].rank_);
    pc->set_last_contact(list[a].last_contact_);
  }

  // Clear the values from the session
  ASSERT_TRUE(ss_->ResetSession());

  // Load the values from the DA
  std::list<PublicContact> contacts;
  for (int y = 0; y < da.contacts_size(); ++y) {
    PublicContact pc = da.contacts(y);
    contacts.push_back(pc);
  }
  ASSERT_EQ(0, ss_->LoadContacts(&contacts));

  // Get values from session again
  std::vector<mi_contact> second_list;
  ASSERT_EQ(0, ss_->GetContactList(&second_list));
  ASSERT_EQ(static_cast<unsigned int>(10), second_list.size());

  // Check the initial values against the seconda values
  for (unsigned int e = 0; e < second_list.size(); ++e) {
    ASSERT_EQ(list[e].pub_name_, second_list[e].pub_name_);
    ASSERT_EQ(list[e].pub_key_, second_list[e].pub_key_);
    ASSERT_EQ(list[e].full_name_, second_list[e].full_name_);
    ASSERT_EQ(list[e].office_phone_, second_list[e].office_phone_);
    ASSERT_EQ(list[e].birthday_, second_list[e].birthday_);
    ASSERT_EQ(list[e].gender_, second_list[e].gender_);
    ASSERT_EQ(list[e].language_, second_list[e].language_);
    ASSERT_EQ(list[e].country_, second_list[e].country_);
    ASSERT_EQ(list[e].city_, second_list[e].city_);
    ASSERT_EQ(list[e].confirmed_, second_list[e].confirmed_);
    ASSERT_EQ(list[e].rank_, second_list[e].rank_);
    ASSERT_EQ(list[e].last_contact_, second_list[e].last_contact_);
  }
}

TEST_F(SessionSingletonTest, BEH_MAID_SessionPrivateSharesIO) {
  // Add shares to the session
  for (int n = 0; n < 10; n++) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + base::itos(n));
    atts.push_back("MSID_" + base::itos(n));
    atts.push_back("MSID_PUB_KEY_" + base::itos(n));
    atts.push_back("MSID_PRI_KEY_" + base::itos(n));

    // Participants
    std::list<maidsafe::ShareParticipants> cp;
    for (int a = 0; a < n + 1; a++) {
      maidsafe::ShareParticipants sps;
      sps.id = "PUB_NAME_" + base::itos(n) + "_" + base::itos(a);
      sps.public_key = "PUB_NAME_PUB_KEY_" + base::itos(n) +
                       "_" + base::itos(a);
      sps.role = 'C';
      cp.push_back(sps);
    }

    // Add private share
    ASSERT_EQ(0, ss_->AddPrivateShare(atts, &cp)) <<
              "Failed to add share";
  }

  // Check shares are in session
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->GetFullShareList(&ps_list));
  ASSERT_EQ(static_cast<unsigned int>(10), ps_list.size());
  std::list<PrivateShare> ps_list1 = ps_list;

  // Move contacts to a DA
  DataAtlas da;
  while (!ps_list.empty()) {
    PrivateShare this_ps = ps_list.front();
    Share *sh = da.add_shares();
    sh->set_name(this_ps.Name());
    sh->set_msid(this_ps.Msid());
    sh->set_msid_pub_key(this_ps.MsidPubKey());
    sh->set_msid_pri_key(this_ps.MsidPriKey());
    std::list<ShareParticipants> this_sp_list = this_ps.Participants();
    while (!this_sp_list.empty()) {
      ShareParticipants this_sp = this_sp_list.front();
      ShareParticipant *shp = sh->add_participants();
      shp->set_public_name(this_sp.id);
      shp->set_public_name_pub_key(this_sp.public_key);
      std::string role(1, this_sp.role);
      shp->set_role(role);
      this_sp_list.pop_front();
    }
    ps_list.pop_front();
  }

  // Clear the values from the session
  ASSERT_TRUE(ss_->ResetSession());

  // Load the values from the DA
  std::list<Share> shares;
  for (int n = 0; n < da.shares_size(); ++n) {
    Share sh = da.shares(n);
    shares.push_back(sh);
  }
  ss_->LoadShares(&shares);

  // Get values from session again
  std::list<PrivateShare> ps_list2;
  ASSERT_EQ(0, ss_->GetFullShareList(&ps_list2));
  ASSERT_EQ(static_cast<unsigned int>(10), ps_list2.size());

  // Check the initial values against the seconda values
  while (!ps_list1.empty()) {
    PrivateShare ps1 = ps_list1.front();
    PrivateShare ps2 = ps_list2.front();
    ASSERT_EQ(ps1.Name(), ps2.Name());
    ASSERT_EQ(ps1.Msid(), ps2.Msid());
    ASSERT_EQ(ps1.MsidPubKey(), ps2.MsidPubKey());
    ASSERT_EQ(ps1.MsidPriKey(), ps2.MsidPriKey());
    std::list<ShareParticipants> sp_list1 = ps1.Participants();
    std::list<ShareParticipants> sp_list2 = ps2.Participants();
    ASSERT_EQ(sp_list1.size(), sp_list2.size());
    while (!sp_list1.empty()) {
      ShareParticipants this_sp1 = sp_list1.front();
      ShareParticipants this_sp2 = sp_list2.front();
      ASSERT_EQ(this_sp1.id, this_sp2.id);
      ASSERT_EQ(this_sp1.public_key, this_sp2.public_key);
      ASSERT_EQ(this_sp1.role, this_sp2.role);
      sp_list1.pop_front();
      sp_list2.pop_front();
    }
    ps_list1.pop_front();
    ps_list2.pop_front();
  }
}

}  // namespace maidsafe
