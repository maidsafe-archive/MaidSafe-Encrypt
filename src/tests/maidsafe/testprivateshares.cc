/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe private shares
* Version:      1.0
* Created:      2009-01-28-23.19.56
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh)
*               alias "The Hutch"
*               fraser.hutchison@maidsafe.net
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
#include <boost/filesystem.hpp>
#include "maidsafe/client/privateshares.h"
#include "maidsafe/utils.h"

void RefillParticipants(std::list<maidsafe::ShareParticipants> *participants) {
  participants->clear();
  maidsafe::ShareParticipants r;
  r.id = "Dan";
  r.public_key = base::RandomString(512);
  r.role = 'R';
  participants->push_back(r);
  r.id = "The Hutch";
  r.public_key = base::RandomString(512);
  r.role = 'A';
  participants->push_back(r);
}

static int test = 0;

class PrivateSharesTest : public testing::Test {
  protected:
    maidsafe::PrivateShareHandler *psh_;
    maidsafe::PrivateShare *ps_;
    std::string name;
    std::list<maidsafe::ShareParticipants> participants;
    std::vector<std::string> attributes;

    PrivateSharesTest() : psh_(NULL), ps_(NULL),
      name(), participants(),
      attributes() {
    }
    PrivateSharesTest(const PrivateSharesTest&);
    PrivateSharesTest& operator=(const PrivateSharesTest&) {
      return *this;
    }

    virtual void SetUp() {
      name = "PrivateShares.db";
      psh_ = new maidsafe::PrivateShareHandler();
      std::string share_name("My First Share");
      attributes.push_back(share_name);
      attributes.push_back(base::RandomString(64));
      attributes.push_back(base::RandomString(512));
      attributes.push_back(base::RandomString(512));
      maidsafe::ShareParticipants r;
      r.id = "Dan";
      r.public_key = base::RandomString(512);
      r.role = 'R';
      participants.push_back(r);
      r.id = "The Hutch";
      r.public_key = base::RandomString(512);
      r.role = 'A';
      participants.push_back(r);
      ps_ = new maidsafe::PrivateShare(attributes, participants);
    }

    virtual void TearDown() {
      delete psh_;
      delete ps_;
      std::string s("PrivateShares.db.");
      s += base::itos(test);
      if (boost::filesystem::exists(s))
        boost::filesystem::remove(s);
      if (boost::filesystem::exists(name)) {
        boost::filesystem::copy_file(name, s);
        boost::filesystem::remove(name);
      }
    }
};

TEST_F(PrivateSharesTest, BEH_MAID_CreateDB_ListPrivateShares) {
  test = 0;
  ASSERT_EQ(0, psh_->CreatePrivateShareDB(name)) <<
    "Problem creating the DB." << std::endl;
  std::list<maidsafe::PrivateShare> list;
  std::string pub_name("");
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(0), list.size()) <<
    "List came back not empty after DB creation.";
  test++;
}

TEST_F(PrivateSharesTest, BEH_MAID_AddPrivateShares) {
  ASSERT_EQ(0, psh_->CreatePrivateShareDB(name)) <<
    "Problem creating the DB." << std::endl;
  std::list<maidsafe::PrivateShare> list;
  std::string pub_name("");
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(0), list.size()) <<
    "List came back not empty after DB creation.";

  std::string msid1 = attributes[1];
  ASSERT_EQ(0, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back not empty after DB creation.";

  list.clear();
  RefillParticipants(&participants);
  ASSERT_EQ(-2205, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
#ifdef DEBUG
  printf("The above error is expected in the test.\n");
#endif
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back not empty after DB creation.";
  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(static_cast<unsigned int>(2), temp.Participants().size()) <<
      "List of participants wrong in size.";
  }

  attributes[0] = "My Next Share";
  attributes[1] = base::RandomString(64);
  attributes[2] = base::RandomString(512);
  attributes[3] = base::RandomString(512);
  std::string msid2 = attributes[1];

  list.clear();
  participants.clear();
  ASSERT_EQ(-2205, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back not empty after DB creation.";
  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(static_cast<unsigned int>(2), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }

  list.clear();
  RefillParticipants(&participants);
  ASSERT_EQ(0, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(2), list.size()) <<
    "List came back not empty after DB creation.";
  int n = 0;
  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    if (n == 0)
      ASSERT_EQ(msid1, temp.Msid()) << "Wrong MSID from DB";
    else
      ASSERT_EQ(msid2, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(2), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
    ++n;
  }

  test++;
}

TEST_F(PrivateSharesTest, BEH_MAID_DeletePrivateShare) {
  ASSERT_EQ(0, psh_->CreatePrivateShareDB(name)) <<
    "Problem creating the DB." << std::endl;
  std::list<maidsafe::PrivateShare> list;
  std::string pub_name("");
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(0), list.size()) <<
    "List came back not empty after DB creation.";

  std::string msid1 = attributes[1];
  ASSERT_EQ(0, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back empty after addition.";

  attributes[0] = "MyNextShare";
  attributes[1] = base::RandomString(64);
  attributes[2] = base::RandomString(512);
  attributes[3] = base::RandomString(512);
  std::string msid2 = attributes[1];

  list.clear();
  RefillParticipants(&participants);
  ASSERT_EQ(0, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(2), list.size()) <<
    "List came back with wrong number of elements.";
  int n = 0;
  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    if (n == 0)
      ASSERT_EQ(msid1, temp.Msid()) << "Wrong MSID from DB";
    else
      ASSERT_EQ(msid2, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(2), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
    ++n;
  }

  list.clear();
  ASSERT_EQ(0, psh_->DeletePrivateShare(name, msid1, 0)) <<
    "Failure on private share deletion.";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back with wrong number of elements.";
  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(msid2, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(2), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }

  list.clear();
  std::string s("MyNextShare");
  ASSERT_EQ(0, psh_->DeletePrivateShare(name, s, 1)) <<
    "Failure on private share deletion.";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(0), list.size()) <<
    "List came back not empty after deletion.";

  test++;
}

TEST_F(PrivateSharesTest, BEH_MAID_ContactAddDeletePrivateShare) {
  ASSERT_EQ(0, psh_->CreatePrivateShareDB(name)) <<
    "Problem creating the DB." << std::endl;
  std::list<maidsafe::PrivateShare> list;
  std::string pub_name("");
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(0), list.size()) <<
    "List came back not empty after DB creation.";

  std::string share_name = attributes[0];
  std::string msid1 = attributes[1];
  ASSERT_EQ(0, psh_->AddPrivateShare(name, attributes, &participants)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back empty after addition.";

  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(msid1, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(2), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }

  std::list<maidsafe::ShareParticipants> newContacts;
  maidsafe::ShareParticipants r;
  r.id = "El jefe";
  r.public_key = base::RandomString(512);
  r.role = 'A';
  newContacts.push_back(r);
  ASSERT_EQ(0, psh_->AddContactsToPrivateShare(name, &newContacts, msid1, 0))
    << "Failed to add Contact via MSID";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back empty after addition.";

  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(msid1, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(3), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }

  newContacts.clear();
  for (int n = 1; n < 6; ++n) {
    maidsafe::ShareParticipants r;
    r.id = "El naco" + base::itos(n);
    r.public_key = base::RandomString(512);
    r.role = 'R';
    newContacts.push_back(r);
  }
  ASSERT_EQ(0, psh_->AddContactsToPrivateShare(
    name, &newContacts, share_name, 1)) <<
    "Failed to add Contacts via Share name";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back empty after addition.";

  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(msid1, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(8), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }

  newContacts.clear();
  for (int n = 2; n < 5; ++n) {
    maidsafe::ShareParticipants r;
    r.id = "El naco" + base::itos(n);
    newContacts.push_back(r);
  }
  ASSERT_EQ(0, psh_->DeleteContactsFromPrivateShare(name, &newContacts)) <<
    "Deletion of Contacts from private share failed";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back empty after addition.";

  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(msid1, temp.Msid()) << "Wrong MSID from DB";
    ASSERT_EQ(static_cast<unsigned int>(5), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }
  test++;
}

TEST_F(PrivateSharesTest, BEH_MAID_AddReceivedPrivateShare) {
  ASSERT_EQ(0, psh_->CreatePrivateShareDB(name)) <<
    "Problem creating the DB." << std::endl;
  std::list<maidsafe::PrivateShare> list;
  std::string pub_name("");
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(0), list.size()) <<
    "List came back not empty after DB creation.";

  std::string msid1 = attributes[1];
  ASSERT_EQ(0, psh_->AddReceivedShare(name, attributes)) <<
    "Problem adding a private share";
  ASSERT_EQ(0, psh_->GetPrivateShareList(name, &list, "", 3)) <<
    "Problem getting whole private share list";
  ASSERT_EQ(static_cast<unsigned int>(1), list.size()) <<
    "List came back not empty after received share insertion.";
  while (!list.empty()) {
    maidsafe::PrivateShare temp = list.front();
    list.pop_front();
    ASSERT_EQ(static_cast<unsigned int>(0), temp.Participants().size()) <<
      "List of participants wrong in size: " << temp.Name();
  }
  test++;
}

TEST_F(PrivateSharesTest, BEH_MAID_MI_Create_ListShares) {
  // Test share list to be empty
  std::list<maidsafe::private_share> share_list;
  ASSERT_EQ(0, psh_->MI_GetShareList(&share_list)) << "Failed getting list.";
  ASSERT_EQ(0, share_list.size()) << "Share container not empty on creation.";

  // Test full share list to be empty
  std::list<maidsafe::PrivateShare> full_share_list;
  ASSERT_EQ(0, psh_->MI_GetFullShareList(&full_share_list)) <<
            "Failed getting full list";
  ASSERT_EQ(0, full_share_list.size()) <<
            "Share container not empty on creation.";

  // Test lower bound of field index
  maidsafe::PrivateShare ps;
  ASSERT_EQ(-2014, psh_->MI_GetShareInfo("aaa", -1, &ps)) <<
            "Failed to recognise invalid field (-1).";
  ASSERT_EQ("", ps.Name()) << "Share container Name was modified.";
  ASSERT_EQ("", ps.Msid()) << "Share container Msid was modified.";
  ASSERT_EQ("", ps.MsidPubKey()) << "Share container MsidPubKey was modified.";
  ASSERT_EQ("", ps.MsidPriKey()) << "Share container MsidPriKey was modified.";
  ASSERT_EQ(0, ps.Participants().size()) <<
            "Share container Participants was modified.";

  // Test upper bound of field index
  ASSERT_EQ(-2014, psh_->MI_GetShareInfo("aaa", 2, &ps)) <<
            "Failed to recognise invalid field (2).";
  ASSERT_EQ("", ps.Name()) << "Share container Name was modified.";
  ASSERT_EQ("", ps.Msid()) << "Share container Msid was modified.";
  ASSERT_EQ("", ps.MsidPubKey()) << "Share container MsidPubKey was modified.";
  ASSERT_EQ("", ps.MsidPriKey()) << "Share container MsidPriKey was modified.";
  ASSERT_EQ(0, ps.Participants().size()) <<
            "Share container Participants was modified.";

  // Test wrong share name
  ASSERT_EQ(-2014, psh_->MI_GetShareInfo("aaa", 0, &ps)) <<
            "Failed to recognise invalid share name.";
  ASSERT_EQ("", ps.Name()) << "Share container Name was modified.";
  ASSERT_EQ("", ps.Msid()) << "Share container Msid was modified.";
  ASSERT_EQ("", ps.MsidPubKey()) << "Share container MsidPubKey was modified.";
  ASSERT_EQ("", ps.MsidPriKey()) << "Share container MsidPriKey was modified.";
  ASSERT_EQ(0, ps.Participants().size()) <<
            "Share container Participants was modified.";

  // Test wrong share msid
  ASSERT_EQ(-2014, psh_->MI_GetShareInfo("aaa", 1, &ps)) <<
            "Failed to recognise invalid share msid.";
  ASSERT_EQ("", ps.Name()) << "Share container Name was modified.";
  ASSERT_EQ("", ps.Msid()) << "Share container Msid was modified.";
  ASSERT_EQ("", ps.MsidPubKey()) << "Share container MsidPubKey was modified.";
  ASSERT_EQ("", ps.MsidPriKey()) << "Share container MsidPriKey was modified.";
  ASSERT_EQ(0, ps.Participants().size()) <<
            "Share container Participants was modified.";

  // Test wrong index for field in share participant lookup
  std::list<maidsafe::share_participant> sp_list;
  ASSERT_EQ(-2015, psh_->MI_GetParticipantsList("aaa", -1, &sp_list)) <<
            "Failed to recognise lower bound.";
  ASSERT_EQ(0, sp_list.size()) << "List should have remained empty.";
  ASSERT_EQ(-2015, psh_->MI_GetParticipantsList("aaa", 2, &sp_list)) <<
            "Failed to recognise upper bound.";
  ASSERT_EQ(0, sp_list.size()) << "List should have remained empty.";

  // Test wrong share name for participant list
  ASSERT_EQ(-2015, psh_->MI_GetParticipantsList("aaa", 0, &sp_list)) <<
            "Failed to recognise invalid share name.";
  ASSERT_EQ(0, sp_list.size()) << "List should have remained empty.";

  // Test wrong share msid for participant list
  ASSERT_EQ(-2015, psh_->MI_GetParticipantsList("aaa", 1, &sp_list)) <<
            "Failed to recognise invalid share msid.";
  ASSERT_EQ(0, sp_list.size()) << "List should have remained empty.";

}

/*
TEST_F(PrivateSharesTest, BEH_MAID_MI_AddShares) {
  // Test share list to be empty
  std::list<maidsafe::private_share> share_list;
  ASSERT_EQ(0, psh_->MI_GetShareList(&share_list)) << "Failed getting list.";
  ASSERT_EQ(0, share_list.size()) << "Share container not empty on creation.";

  // Add private share
  ASSERT_EQ(0, psh_->MI_AddPrivateShare(attributes, &participants)) <<
            "Failed to add share";
  printf("1\n");
  // Check with GetShareInfo
  maidsafe::PrivateShare by_name;
  ASSERT_EQ(0, psh_->MI_GetShareInfo(attributes[0], 0, &by_name)) <<
            "Failed to locate share by name";
  printf("2\n");
  ASSERT_EQ(attributes[0], by_name.Name()) << "Name different";
  printf("3\n");
  ASSERT_EQ(attributes[1], by_name.Msid()) << "Msid different";
  printf("4\n");
  ASSERT_EQ(attributes[2], by_name.MsidPubKey()) << "MsidPubKey different";
  printf("5\n");
  ASSERT_EQ(attributes[3], by_name.MsidPriKey()) << "MsidPriKey different";
  printf("6\n");
  ASSERT_EQ(participants.size(), by_name.Participants().size()) <<
            "Participant lists different in size.";
  printf("7\n");
  maidsafe::PrivateShare by_msid;
  ASSERT_EQ(0, psh_->MI_GetShareInfo(attributes[1], 1, &by_msid)) <<
            "Failed to locate share by msid";
  ASSERT_EQ(attributes[0], by_msid.Name()) << "Name different";
  ASSERT_EQ(attributes[1], by_msid.Msid()) << "Msid different";
  ASSERT_EQ(attributes[2], by_msid.MsidPubKey()) << "MsidPubKey different";
  ASSERT_EQ(attributes[3], by_msid.MsidPriKey()) << "MsidPriKey different";
  ASSERT_EQ(participants.size(), by_msid.Participants().size()) <<
            "Participant lists different in size.";
}
*/
