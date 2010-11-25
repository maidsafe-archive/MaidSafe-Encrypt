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

#include "maidsafe/common/commonutils.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/sharedtest/cachepassport.h"

namespace maidsafe {

namespace test {

class SessionSingletonTest : public testing::Test {
 public:
  SessionSingletonTest() : ss_(SessionSingleton::getInstance()) {}

 protected:
  void SetUp() {
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss_->passport_ = passport;
    ss_->ResetSession();
  }
  void TearDown() {
    ss_->ResetSession();
  }
  SessionSingleton *ss_;

 private:
  explicit SessionSingletonTest(const SessionSingletonTest&);
  SessionSingletonTest &operator=(const SessionSingletonTest&);
};

TEST_F(SessionSingletonTest, BEH_MAID_SetsGetsAndResetSession) {
  // Check session is clean originally
  ASSERT_FALSE(ss_->DaModified());
  ASSERT_EQ(kDefCon3, ss_->DefConLevel());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ("", ss_->PublicUsername());
  ASSERT_EQ("", ss_->SessionName());
  ASSERT_EQ("", ss_->RootDbKey());
  ASSERT_EQ(size_t(0), ss_->AuthorisedUsers().size());
  ASSERT_EQ(size_t(0), ss_->MaidAuthorisedUsers().size());
  ASSERT_EQ(0, ss_->Mounted());
  ASSERT_EQ('\0', ss_->WinDrive());
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(0), list.size());
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->GetFullShareList(ALPHA, kAll, &ps_list));
  ASSERT_EQ(size_t(0), ps_list.size());

  // Modify session
  ASSERT_TRUE(ss_->SetDaModified(true));
  ASSERT_TRUE(ss_->SetDefConLevel(kDefCon1));
  ASSERT_TRUE(ss_->SetUsername("aaa"));
  ASSERT_TRUE(ss_->SetPin("bbb"));
  ASSERT_TRUE(ss_->SetPassword("ccc"));
  ASSERT_TRUE(ss_->SetPublicUsername("Dan Schmidt"));
  ASSERT_TRUE(ss_->SetSessionName(false));
  ASSERT_TRUE(ss_->SetRootDbKey("ddd"));
  std::set<std::string> non_empty_set;
  non_empty_set.insert("eee");
  ASSERT_TRUE(ss_->SetAuthorisedUsers(non_empty_set));
  non_empty_set.insert("fff");
  ASSERT_TRUE(ss_->SetMaidAuthorisedUsers(non_empty_set));
  ASSERT_TRUE(ss_->SetMounted(1));
  ASSERT_TRUE(ss_->SetWinDrive('N'));
  ASSERT_EQ(0, ss_->AddContact("pub_name", "pub_key", "full_name",
            "office_phone", "birthday", 'M', 18, 6, "city", 'C', 0, 0));
  std::vector<std::string> attributes;
  attributes.push_back("name");
  attributes.push_back("msid");
  attributes.push_back("msid_pub_key");
  attributes.push_back("msid_pri_key");
  std::list<ShareParticipants> participants;
  participants.push_back(ShareParticipants("id", "id_pub_key", 'A'));
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(0, ss_->AddPrivateShare(attributes, share_stats, &participants));

  // Verify modifications
  ASSERT_TRUE(ss_->DaModified());
  ASSERT_EQ(kDefCon1, ss_->DefConLevel());
  ASSERT_EQ("aaa", ss_->Username());
  ASSERT_EQ("bbb", ss_->Pin());
  ASSERT_EQ("ccc", ss_->Password());
  ASSERT_EQ("Dan Schmidt", ss_->PublicUsername());
  ASSERT_NE("", ss_->SessionName());
  ASSERT_EQ("ddd", ss_->RootDbKey());
  ASSERT_EQ(size_t(1), ss_->AuthorisedUsers().size());
  std::set<std::string>::const_iterator it = ss_->AuthorisedUsers().find("eee");
  ASSERT_FALSE(ss_->AuthorisedUsers().end() == it);
  ASSERT_EQ(size_t(2), ss_->MaidAuthorisedUsers().size());
  it = ss_->MaidAuthorisedUsers().find("eee");
  ASSERT_FALSE(ss_->MaidAuthorisedUsers().end() == it);
  it = ss_->MaidAuthorisedUsers().find("fff");
  ASSERT_FALSE(ss_->MaidAuthorisedUsers().end() == it);
  ASSERT_EQ(1, ss_->Mounted());
  ASSERT_EQ('N', ss_->WinDrive());
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(1), list.size());
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
  ASSERT_EQ(0, ss_->GetFullShareList(ALPHA, kAll, &ps_list));
  ASSERT_EQ(size_t(1), ps_list.size());
  ASSERT_EQ("name", ps_list.front().Name());
  ASSERT_EQ("msid", ps_list.front().Msid());
  ASSERT_EQ("msid_pub_key", ps_list.front().MsidPubKey());
  ASSERT_EQ("msid_pri_key", ps_list.front().MsidPriKey());
  std::list<ShareParticipants> sp_list = ps_list.front().Participants();
  ASSERT_EQ(size_t(1), sp_list.size());
  ASSERT_EQ("id", sp_list.front().id);
  ASSERT_EQ("id_pub_key", sp_list.front().public_key);
  ASSERT_EQ('A', sp_list.front().role);

  // Resetting the session
  ASSERT_TRUE(ss_->ResetSession());

  // Check session is clean again
  ASSERT_FALSE(ss_->DaModified());
  ASSERT_EQ(kDefCon3, ss_->DefConLevel());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  ASSERT_EQ("", ss_->PublicUsername());
  ASSERT_EQ("", ss_->SessionName());
  ASSERT_EQ("", ss_->RootDbKey());
  ASSERT_EQ(size_t(0), ss_->AuthorisedUsers().size());
  ASSERT_EQ(size_t(0), ss_->MaidAuthorisedUsers().size());
  ASSERT_EQ(0, ss_->Mounted());
  ASSERT_EQ('\0', ss_->WinDrive());
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(0), list.size());
  ASSERT_EQ(0, ss_->GetFullShareList(ALPHA, kAll, &ps_list));
  ASSERT_EQ(size_t(0), ps_list.size());
}

TEST_F(SessionSingletonTest, BEH_MAID_SessionName) {
  // Check session is empty
  ASSERT_EQ("", ss_->SessionName());
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());

  // Check username and pin are needed
  ASSERT_FALSE(ss_->SetSessionName(false));
  ASSERT_EQ("", ss_->SessionName());

  std::string username("user1");
  std::string pin("1234");
  std::string session_name = base::EncodeToHex(SHA1String(pin + username));

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

TEST_F(SessionSingletonTest, BEH_MAID_SessionContactsIO) {
  // Add contacts to the session
  for (int n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + base::IntToString(n),
              "pub_key_" + base::IntToString(n),
              "full_name_" + base::IntToString(n),
              "office_phone_" + base::IntToString(n),
              "birthday_" + base::IntToString(n),
              'M', n, n, "city_" + base::IntToString(n), 'C', 0, 0));
  }

  // Check contacts are in session
  std::vector<mi_contact> list;
  ASSERT_EQ(0, ss_->GetContactList(&list));
  ASSERT_EQ(size_t(10), list.size());

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
  ASSERT_EQ(size_t(10), second_list.size());

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
  std::vector<boost::uint32_t> share_stats(2, 2);
  for (int n = 0; n < 10; n++) {
    // Attributes
    std::vector<std::string> atts;
    atts.push_back("NAME_" + base::IntToString(n));
    atts.push_back("MSID_" + base::IntToString(n));
    atts.push_back("MSID_PUB_KEY_" + base::IntToString(n));
    atts.push_back("MSID_PRI_KEY_" + base::IntToString(n));

    // Participants
    std::list<maidsafe::ShareParticipants> cp;
    for (int a = 0; a <= n; a++) {
      maidsafe::ShareParticipants sps;
      sps.id = "PUB_NAME_" + base::IntToString(n) + "_" + base::IntToString(a);
      sps.public_key = "PUB_NAME_PUB_KEY_" + base::IntToString(n) +
                       "_" + base::IntToString(a);
      sps.role = 'C';
      cp.push_back(sps);
    }

    // Add private share
    ASSERT_EQ(0, ss_->AddPrivateShare(atts, share_stats, &cp)) <<
              "Failed to add share";
  }

  // Check shares are in session
  std::list<PrivateShare> ps_list;
  ASSERT_EQ(0, ss_->GetFullShareList(ALPHA, kAll, &ps_list));
  ASSERT_EQ(size_t(10), ps_list.size());
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
    sh->set_rank(this_ps.Rank());
    sh->set_last_view(this_ps.LastViewed());
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
  ASSERT_EQ(0, ss_->GetFullShareList(ALPHA, kAll, &ps_list2));
  ASSERT_EQ(size_t(10), ps_list2.size());

  // Check the initial values against the seconda values
  while (!ps_list1.empty()) {
    PrivateShare ps1 = ps_list1.front();
    PrivateShare ps2 = ps_list2.front();
    ASSERT_EQ(ps1.Name(), ps2.Name());
    ASSERT_EQ(ps1.Msid(), ps2.Msid());
    ASSERT_EQ(ps1.MsidPubKey(), ps2.MsidPubKey());
    ASSERT_EQ(ps1.MsidPriKey(), ps2.MsidPriKey());
    ASSERT_EQ(ps1.Rank(), ps2.Rank());
    ASSERT_EQ(ps1.LastViewed(), ps2.LastViewed());
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

TEST_F(SessionSingletonTest, BEH_MAID_PubUsernameList) {
  for (size_t n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + base::IntToString(n),
              "pub_key_" + base::IntToString(n),
              "full_name_" + base::IntToString(n),
              "office_phone_" + base::IntToString(n),
              "birthday_" + base::IntToString(n),
              'M', n, n, "city_" + base::IntToString(n), 'C', 0, 0));
  }
  std::vector<std::string> publicusernames;
  ASSERT_EQ(0, ss_->GetPublicUsernameList(&publicusernames));
  ASSERT_EQ(size_t(10), publicusernames.size());
  for (size_t a = 0; a < publicusernames.size(); ++a)
    ASSERT_EQ("pub_name_" + base::IntToString(a), publicusernames[a]);
}

TEST_F(SessionSingletonTest, BEH_MAID_ContactPublicKey) {
  for (size_t n = 0; n < 10; n++) {
    ASSERT_EQ(0, ss_->AddContact("pub_name_" + base::IntToString(n),
              "pub_key_" + base::IntToString(n),
              "full_name_" + base::IntToString(n),
              "office_phone_" + base::IntToString(n),
              "birthday_" + base::IntToString(n),
              'M', n, n, "city_" + base::IntToString(n), 'C', 0, 0));
  }
  for (size_t a = 0; a < 10; ++a)
    ASSERT_EQ("pub_key_" + base::IntToString(a),
              ss_->GetContactPublicKey("pub_name_" + base::IntToString(a)));
}

TEST_F(SessionSingletonTest, BEH_MAID_Conversations) {
  std::list<std::string> conv;
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());
  conv.push_back("a");
  ASSERT_EQ(size_t(1), conv.size());
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());
  ASSERT_EQ(kNonExistentConversation, ss_->ConversationExits("a"));
  ASSERT_EQ(kNonExistentConversation, ss_->RemoveConversation("a"));

  ASSERT_EQ(0, ss_->AddConversation("a"));
  ASSERT_EQ(0, ss_->ConversationExits("a"));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(1), conv.size());
  ASSERT_EQ("a", conv.front());
  ASSERT_EQ(kExistingConversation, ss_->AddConversation("a"));
  ASSERT_EQ(0, ss_->RemoveConversation("a"));
  ASSERT_EQ(kNonExistentConversation, ss_->ConversationExits("a"));
  ASSERT_EQ(kNonExistentConversation, ss_->RemoveConversation("a"));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());

  for (int n = 0; n < 10; ++n)
    ASSERT_EQ(0, ss_->AddConversation(base::IntToString(n)));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(10), conv.size());

  std::string remove = base::IntToString(base::RandomUint32() % 10);
  ASSERT_EQ(0, ss_->RemoveConversation(remove));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(9), conv.size());
  std::list<std::string>::iterator it;
  for (it = conv.begin(); it != conv.end(); ++it) {
    int a = boost::lexical_cast<int>(*it);
    ASSERT_TRUE(a > -1 && a < 10);
    ASSERT_EQ(0, ss_->RemoveConversation(*it));
  }
  for (int y = 0; y < 10; ++y)
    ASSERT_EQ(kNonExistentConversation,
              ss_->ConversationExits(base::IntToString(y)));

  for (int e = 0; e < 10; ++e)
    ASSERT_EQ(0, ss_->AddConversation(base::IntToString(e)));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(10), conv.size());
  ss_->ClearConversations();
  for (int l = 0; l < 10; ++l)
    ASSERT_EQ(kNonExistentConversation,
              ss_->ConversationExits(base::IntToString(l)));
  ASSERT_EQ(0, ss_->ConversationList(&conv));
  ASSERT_EQ(size_t(0), conv.size());
}

TEST_F(SessionSingletonTest, BEH_MAID_LiveContacts) {
  // Verify LiveContacts are empty after reset
  std::list<std::string> contacts;
  ASSERT_EQ(0, ss_->LivePublicUsernameList(&contacts));
  ASSERT_EQ(size_t(0), contacts.size());
  std::map<std::string, ConnectionDetails> live_contacts;
  ASSERT_EQ(0, ss_->LiveContactMap(&live_contacts));
  ASSERT_EQ(size_t(0), live_contacts.size());

  // Modify non-existent contact
  std::string non_existent_contact("nalgabert");
  EndPoint end_points;
  boost::uint16_t transport_id;
  boost::uint32_t connection_id;
  int status;
  boost::uint32_t timestamp;
  ASSERT_EQ(kLiveContactNotFound, ss_->LiveContactDetails(non_existent_contact,
            &end_points, &transport_id, &connection_id, &status, &timestamp));
  ASSERT_EQ(kLiveContactNotFound, ss_->LiveContactTransportConnection(
            non_existent_contact, &transport_id, &connection_id));
  transport_id = 2;
  connection_id = 23654;
  ASSERT_EQ(kLiveContactNotFound, ss_->StartLiveConnection(
            non_existent_contact, transport_id, connection_id));
  ASSERT_EQ(kLiveContactNotFound,
            ss_->ModifyTransportId(non_existent_contact, transport_id));
  ASSERT_EQ(kLiveContactNotFound,
            ss_->ModifyConnectionId(non_existent_contact, connection_id));
  for (int n = 0; n < 3; ++n)
    ASSERT_EQ(kLiveContactNotFound,
              ss_->ModifyEndPoint(non_existent_contact, "IP", 1, n));
  ASSERT_EQ(kLiveContactNoEp,
            ss_->ModifyEndPoint(non_existent_contact, "IP", 1, -1));
  ASSERT_EQ(kLiveContactNoEp,
            ss_->ModifyEndPoint(non_existent_contact, "IP", 1, 3));
  ASSERT_EQ(kLiveContactNotFound, ss_->ModifyStatus(non_existent_contact, 7));
  ASSERT_EQ(0, ss_->DeleteLiveContact(non_existent_contact));

  // Adding a contact
  std::string contact_a("ava");
  end_points.Clear();
  for (int n = 0; n < 3; ++n) {
    end_points.add_ip("192.168.1." + base::IntToString(n));
    end_points.add_port(64000 + n);
  }
  ASSERT_EQ(0, ss_->AddLiveContact(contact_a, end_points, 7));
  ASSERT_EQ(kAddLiveContactFailure,
            ss_->AddLiveContact(contact_a, end_points, 7));

  // Verifying details of added contact
  EndPoint inserted_eps(end_points);
  ASSERT_EQ(0, ss_->LivePublicUsernameList(&contacts));
  ASSERT_EQ(size_t(1), contacts.size());
  ASSERT_EQ(contact_a, contacts.front());
  ASSERT_EQ(0, ss_->LiveContactMap(&live_contacts));
  ASSERT_EQ(size_t(1), live_contacts.size());
  SessionSingleton::live_map::iterator it = live_contacts.find(contact_a);
  ASSERT_FALSE(live_contacts.end() == it);
  ASSERT_EQ(0, ss_->LiveContactDetails(contact_a, &end_points, &transport_id,
            &connection_id, &status, &timestamp));
  for (int n = 0; n < 3; ++n) {
    ASSERT_EQ(inserted_eps.ip(n), end_points.ip(n));
    ASSERT_EQ(inserted_eps.port(n), end_points.port(n));
  }
  ASSERT_EQ(boost::uint32_t(0), transport_id);
  ASSERT_EQ(boost::uint32_t(0), connection_id);
  ASSERT_EQ(boost::uint32_t(0), timestamp);
  ASSERT_EQ(7, status);
  ASSERT_EQ(0, ss_->LiveContactTransportConnection(contact_a, &transport_id,
            &connection_id));
  ASSERT_EQ(boost::uint32_t(0), transport_id);
  ASSERT_EQ(boost::uint32_t(0), connection_id);
  ASSERT_EQ(0, ss_->StartLiveConnection(contact_a, 2, 23456));
  ASSERT_EQ(0, ss_->LiveContactDetails(contact_a, &end_points, &transport_id,
            &connection_id, &status, &timestamp));
  ASSERT_EQ(boost::uint32_t(2), transport_id);
  ASSERT_EQ(boost::uint32_t(23456), connection_id);
  boost::uint32_t now = base::GetEpochTime();
  ASSERT_TRUE(timestamp <= now && timestamp > now - 2);

  // Modifying details of added contact
  ASSERT_EQ(0, ss_->ModifyTransportId(contact_a, 3));
  ASSERT_EQ(0, ss_->ModifyConnectionId(contact_a, 33333));
  inserted_eps.Clear();
  for (int n = 0; n < 3; ++n) {
    inserted_eps.add_ip("172.22.18." + base::IntToString(n));
    inserted_eps.add_port(22700 + n);
    ASSERT_EQ(0, ss_->ModifyEndPoint(contact_a,
                                     "172.22.18." + base::IntToString(n),
                                     22700 + n, n));
  }
  ASSERT_EQ(0, ss_->ModifyStatus(contact_a, 2));
  ASSERT_EQ(0, ss_->LiveContactDetails(contact_a, &end_points, &transport_id,
            &connection_id, &status, &timestamp));
  for (int n = 0; n < 3; ++n) {
    ASSERT_EQ(inserted_eps.ip(n), end_points.ip(n));
    ASSERT_EQ(inserted_eps.port(n), end_points.port(n));
  }
  ASSERT_EQ(boost::uint32_t(3), transport_id);
  ASSERT_EQ(boost::uint32_t(33333), connection_id);
  ASSERT_EQ(2, status);
  now = base::GetEpochTime();
  ASSERT_TRUE(timestamp <= now && timestamp > now - 2);

  // Deleting inserted contact
  ASSERT_EQ(1, ss_->DeleteLiveContact(contact_a));

  // Inserting multiple contacts
  int test_contacts(10);
  for (int n = 0; n < test_contacts; ++n) {
    std::string contact_n("ava" + base::IntToString(n));
    end_points.Clear();
    for (int a = 0; a < 3; ++a) {
      end_points.add_ip("192.168." + base::IntToString(n) + "." +
                        base::IntToString(a));
      end_points.add_port(64000 + (n * 10) + a);
    }
    ASSERT_EQ(0, ss_->AddLiveContact(contact_n, end_points, n));
  }
  ASSERT_EQ(0, ss_->LivePublicUsernameList(&contacts));
  ASSERT_EQ(size_t(10), contacts.size());
  std::list<std::string>::iterator cit;
  int y(0);
  int estado;
  for (cit = contacts.begin(); cit != contacts.end(); ++cit) {
    ASSERT_EQ("ava" + base::IntToString(y), *cit);
    ASSERT_EQ(0, ss_->LiveContactStatus(*cit, &estado));
    ASSERT_EQ(y, estado);
    ++y;
  }

  for (int e = 0; e < 10; ++e)
    if ((e%2) == 0)
      ASSERT_EQ(1, ss_->DeleteLiveContact("ava" + base::IntToString(e)));
  ASSERT_EQ(0, ss_->LivePublicUsernameList(&contacts));
  ASSERT_EQ(size_t(5), contacts.size());
  y = 1;
  for (cit = contacts.begin(); cit != contacts.end(); ++cit) {
    ASSERT_EQ("ava" + base::IntToString(y), *cit);
    y += 2;
  }
}

}  // namespace test

}  // namespace maidsafe
