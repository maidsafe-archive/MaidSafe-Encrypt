/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include "maidsafe/client/contacts.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"

class ContactsTest : public testing::Test {
  protected:
    maidsafe::ContactsHandler *sch_;
    std::string name_;
    int test;
    std::vector<std::string> contact_;

    ContactsTest() : sch_(NULL), name_(""), test(0), contact_() {}
    ContactsTest(const ContactsTest&);
    ContactsTest& operator=(const ContactsTest&);

    virtual void SetUp() {
      contact_.push_back("dan.schmidt");
      contact_.push_back("abcdefghijk");
      contact_.push_back("Dan Schmidt Valle");
      contact_.push_back("0123654789");
      contact_.push_back("18061980");
      contact_.push_back("M");
      contact_.push_back("1");
      contact_.push_back("1");
      contact_.push_back("Troon");
      contact_.push_back("C");
      contact_.push_back("0");
      contact_.push_back("-1");

      name_ = "Contacts.db";
      sch_ = new maidsafe::ContactsHandler();
    }

    virtual void TearDown() {
      delete sch_;
      std::string s("Contacts.db.700");
      s += base::itos(test);
      if (boost::filesystem::exists(s))
        boost::filesystem::remove(s);
      if (boost::filesystem::exists(name_)) {
        boost::filesystem::copy_file(name_, s);
        boost::filesystem::remove(name_);
      }
    }
};

TEST_F(ContactsTest, BEH_MAID_CreateDB_ListContacts) {
  test = 0;
  ASSERT_EQ(0, sch_->CreateContactDB(name_)) <<
    "Problem creating the DB." << std::endl;
  std::vector<maidsafe::Contacts> list;
  std::string pub_name("");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";
  test++;
}

TEST_F(ContactsTest, BEH_MAID_AddContacts) {
  ASSERT_EQ(0, sch_->CreateContactDB(name_)) <<
    "Problem creating the DB." << std::endl;
  std::vector<maidsafe::Contacts> list;
  std::string pub_name("");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";

  maidsafe::Contacts msc(contact_);

  ASSERT_EQ(0, sch_->AddContact(name_, msc)) <<
    "Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back empty after addition.";

  maidsafe::Contacts sc;
  sc = list[0];
  ASSERT_EQ(msc.PublicName(), sc.PublicName()) <<
    "Public name from DB not the same as the one inserted.";

  list.clear();
  ASSERT_EQ(-3, sch_->AddContact(name_, msc)) <<
    "Problem adding a contact";
  printf("The above error is expected in the test.\n");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back with more or less entries than it should'ave.";

  list.clear();
  msc.SetPublicName("palo.feo.smer");
  ASSERT_EQ(0, sch_->AddContact(name_, msc)) <<
    "Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)2, list.size()) <<
    "List came back with more or less entries than it should'ave.";

  test++;
}

TEST_F(ContactsTest, BEH_MAID_DeleteContacts) {
  ASSERT_EQ(0, sch_->CreateContactDB(name_)) <<
    "Problem creating the DB." << std::endl;
  std::vector<maidsafe::Contacts> list;
  std::string pub_name("");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";

  maidsafe::Contacts msc(contact_);

  ASSERT_EQ(0, sch_->AddContact(name_, msc)) <<
    "Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back empty after addition.";

  maidsafe::Contacts sc;
  sc = list[0];
  ASSERT_EQ(msc.PublicName(), sc.PublicName()) <<
    "Public name from DB not the same as the one inserted.";

  list.clear();
  ASSERT_EQ(0, sch_->DeleteContact(name_, msc)) <<
    "Problem deleting contact.";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";

  test++;
}

TEST_F(ContactsTest, BEH_MAID_Update_Select_PubName_Contacts) {
  ASSERT_EQ(0, sch_->CreateContactDB(name_)) <<
    "Problem creating the DB." << std::endl;
  std::vector<maidsafe::Contacts> list;
  std::string pub_name("");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";

  maidsafe::Contacts msc(contact_);

  ASSERT_EQ(0, sch_->AddContact(name_, msc)) <<
    "Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back empty after addition.";

  maidsafe::Contacts sc;
  sc = list[0];
  ASSERT_EQ(msc.PublicName(), sc.PublicName()) <<
    "Public name from DB not the same as the one inserted.";

  list.clear();
  maidsafe::Contacts msc1;
  msc1.SetPublicName(msc.PublicName());
  msc1.SetPublicKey("zyxwvutsrq");
  msc1.SetFullName("Andale Tonto");
  msc1.SetBirthday("22071983");
  pub_name = msc1.PublicName();
  ASSERT_EQ(0, sch_->UpdateContact(name_, msc1)) <<
    "Problem modifying contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back with more or less entries than it should'ave.";

  sc = list[0];
  ASSERT_EQ(msc1.PublicName(), sc.PublicName()) <<
    "Public name from DB not the same as the one inserted.";
  ASSERT_EQ(msc1.PublicKey(), sc.PublicKey()) <<
    "Public key from DB not the same as the one inserted.";
  ASSERT_EQ(msc1.FullName(), sc.FullName()) <<
    "Full name from DB not the same as the one inserted.";
  ASSERT_EQ(msc1.Birthday(), sc.Birthday()) <<
    "Birthday from DB not the same as the one inserted.";

  list.clear();
  maidsafe::Contacts msc2;
  msc2.SetPublicName(msc.PublicName());
  msc2.SetConfirmed('U');
  pub_name = msc2.PublicName();
  ASSERT_EQ(0, sch_->UpdateContact(name_, msc2)) <<
    "Problem modifying contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back with more or less entries than it should'ave.";

  sc = list[0];
  ASSERT_EQ(msc2.PublicName(), sc.PublicName()) <<
    "Public name from DB not the same as the one inserted.";
  ASSERT_EQ(msc2.Confirmed(), sc.Confirmed()) <<
    "Status from DB not the same as the one inserted.";

  test++;
}

TEST_F(ContactsTest, BEH_MAID_LastContact_Rank_Contacts) {
  ASSERT_EQ(0, sch_->CreateContactDB(name_)) <<
    "Problem creating the DB." << std::endl;
  std::vector<maidsafe::Contacts> list;
  std::string pub_name("");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";

  maidsafe::Contacts msc(contact_);
  ASSERT_EQ(0, sch_->AddContact(name_, msc)) <<
    "Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back empty after addition.";

  list.clear();
  pub_name = msc.PublicName();
  ASSERT_EQ(0, sch_->SetLastContactRank(name_, msc)) <<
    "Problem modifying contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back with more or less entries than it should'ave.";
  int ct =  base::get_epoch_time();

  maidsafe::Contacts sc;
  sc = list[0];
  ASSERT_TRUE(sc.LastContact() == ct || sc.LastContact() == ct-1) <<
    "Last contact did not update";
  ASSERT_EQ(1, sc.Rank()) << "Rank did not update";

  list.clear();
  ASSERT_EQ(0, sch_->SetLastContactRank(name_, msc)) <<
    "Problem modifying contact";
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)1, list.size()) <<
    "List came back with more or less entries than it should'ave.";
  ct =  base::get_epoch_time();

  sc = list[0];
  ASSERT_TRUE(sc.LastContact() == ct || sc.LastContact() == ct-1) <<
    "Last contact did not update";
  ASSERT_EQ(2, sc.Rank()) << "Rank did not update";

  test++;
}

TEST_F(ContactsTest, BEH_MAID_ListContacts_Rank_LastContact) {
  ASSERT_EQ(0, sch_->CreateContactDB(name_)) <<
    "Problem creating the DB." << std::endl;
  std::vector<maidsafe::Contacts> list;
  std::string pub_name("");
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)0, list.size()) <<
    "List came back not empty after DB creation.";

  for (int n = 1; n < 21; n++) {
    int r = base::random_32bit_uinteger()%122;
    std::vector<std::string> contact;
    contact.push_back("pub_name_" + base::itos(n));
    contact.push_back("pub_key_" + base::itos(n));
    contact.push_back("full_name_" + base::itos(n));
    contact.push_back("office_phone_" + base::itos(n));
    contact.push_back("birthday_" + base::itos(n));
    contact.push_back("M");
    contact.push_back(base::itos(n));
    contact.push_back(base::itos(n));
    contact.push_back("city_" + base::itos(n));
    contact.push_back("C");
    contact.push_back(base::itos(r));
    int rt = base::get_epoch_time()-r;
    contact.push_back(base::itos(rt));
    maidsafe::Contacts c(contact);
    sch_->AddContact(name_, c);
  }

  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)20, list.size()) <<
    "List came back with wrong number of elements.";

  list.clear();
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name, false, 1)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)20, list.size()) <<
    "List came back with wrong number of elements.";

  for (unsigned int n = 0; n < list.size()-1; n++) {
    maidsafe::Contacts cn = list[n];
    maidsafe::Contacts cn_1 = list[n+1];
// std::cout << cn.Rank() << " >= " << cn_1.Rank() << std::endl;
    ASSERT_GE(cn.Rank(), cn_1.Rank()) <<
      "Descending order broken by elements " << n << " and " << n+1;
  }

  list.clear();
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name, false, 2)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)20, list.size()) <<
    "List came back with wrong number of elements.";

  for (unsigned int n = 0; n < list.size()-1; n++) {
    maidsafe::Contacts cn = list[n];
    maidsafe::Contacts cn_1 = list[n+1];
// std::cout << cn.LastContact() << " >= " << cn_1.LastContact() << std::endl;
    ASSERT_GE(cn.LastContact(), cn_1.LastContact()) <<
      "Descending order broken by elements " << n << " and " << n+1;
  }

  for (int n = 21; n < 101; n++) {
    int r = base::random_32bit_uinteger()%122;
    std::vector<std::string> contact;
    contact.push_back("pub_name_" + base::itos(n));
    contact.push_back("pub_key_" + base::itos(n));
    contact.push_back("full_name_" + base::itos(n));
    contact.push_back("office_phone_" + base::itos(n));
    contact.push_back("birthday_" + base::itos(n));
    contact.push_back("M");
    contact.push_back(base::itos(n));
    contact.push_back(base::itos(n));
    contact.push_back("city_" + base::itos(n));
    contact.push_back("C");
    contact.push_back(base::itos(r));
    int rt = base::get_epoch_time()-r;
    contact.push_back(base::itos(rt));
    maidsafe::Contacts c(contact);
    sch_->AddContact(name_, c);
  }

  list.clear();
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name, false, 1)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)50, list.size()) <<
    "List came back with wrong number of elements.";

  for (unsigned int n = 0; n < list.size()-1; n++) {
    maidsafe::Contacts cn = list[n];
    maidsafe::Contacts cn_1 = list[n+1];
//     std::cout << cn.Rank() << " >= " << cn_1.Rank() << std::endl;
    ASSERT_GE(cn.Rank(), cn_1.Rank()) <<
      "Descending order broken by elements " << n << " and " << n+1;
  }

  list.clear();
  ASSERT_EQ(0, sch_->GetContactList(name_, list, pub_name, false, 2)) <<
    "Problem getting contact list";
  ASSERT_EQ((unsigned)50, list.size()) <<
    "List came back with wrong number of elements.";

  for (unsigned int n = 0; n < list.size()-1; n++) {
    maidsafe::Contacts cn = list[n];
    maidsafe::Contacts cn_1 = list[n+1];
// std::cout << cn.LastContact() << " >= " << cn_1.LastContact() << std::endl;
    ASSERT_GE(cn.LastContact(), cn_1.LastContact()) <<
      "Descending order broken by elements " << n << " and " << n+1;
  }

  test++;
}

