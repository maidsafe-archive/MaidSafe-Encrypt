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
#include "base/utils.h"

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
