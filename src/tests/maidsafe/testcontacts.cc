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

#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>
#include "maidsafe/client/contacts.h"

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
      sch_->ClearContacts();
    }

    virtual void TearDown() {
      delete sch_;
    }
};

TEST_F(ContactsTest, BEH_MAID_ContactValueObject) {
  std::string pn("A");
  std::string pk("B");
  std::string fn("C");
  std::string po("D");
  std::string bd("E");
  char g = 'M';
  int l = 22;
  int c = 7;
  std::string ct("F");
  char cf = 'M';
  int r = 22;
  int lc = 7;

  maidsafe::Contact contact;
  ASSERT_TRUE(contact.SetPublicName(pn)) << "Failed to set public name.";
  ASSERT_TRUE(contact.SetPublicKey(pk)) << "Failed to set public key.";
  ASSERT_TRUE(contact.SetFullName(fn)) << "Failed to set full name.";
  ASSERT_TRUE(contact.SetOfficePhone(po)) << "Failed to set office phone.";
  ASSERT_TRUE(contact.SetBirthday(bd)) << "Failed to set birthday.";
  ASSERT_TRUE(contact.SetGender(g)) << "Failed to set gender.";
  ASSERT_TRUE(contact.SetLanguage(l)) << "Failed to set language.";
  ASSERT_TRUE(contact.SetCountry(c)) << "Failed to set country.";
  ASSERT_TRUE(contact.SetCity(ct)) << "Failed to set city.";
  ASSERT_TRUE(contact.SetConfirmed(cf)) << "Failed to set confirmation status.";
  ASSERT_TRUE(contact.SetRank(r)) << "Failed to set rank.";
  ASSERT_TRUE(contact.SetLastContact(lc)) << "Failed to set last contact time.";

  ASSERT_EQ(pn, contact.PublicName()) << "Retrieved public name is incorrect.";
  ASSERT_EQ(pk, contact.PublicKey()) << "Retrieved public key is incorrect.";
  ASSERT_EQ(fn, contact.FullName()) << "Retrieved full name is incorrect.";
  ASSERT_EQ(po, contact.OfficePhone()) <<
            "Retrieved office phone is incorrect.";
  ASSERT_EQ(bd, contact.Birthday()) << "Retrieved birthday is incorrect.";
  ASSERT_EQ(g, contact.Gender()) << "Retrieved gender is incorrect.";
  ASSERT_EQ(l, contact.Language()) << "Retrieved language is incorrect.";
  ASSERT_EQ(c, contact.Country()) << "Retrieved country is incorrect.";
  ASSERT_EQ(ct, contact.City()) << "Retrieved city is incorrect.";
  ASSERT_EQ(cf, contact.Confirmed()) <<
            "Retrieved confirmation status is incorrect.";
  ASSERT_EQ(r, contact.Rank()) << "Retrieved rank is incorrect.";
  ASSERT_EQ(lc, contact.LastContact()) <<
            "Retrieved last contact time is incorrect.";
}

TEST_F(ContactsTest, BEH_MAID_Create_ListContacts) {
  std::vector<maidsafe::mi_contact> mi_list;
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list, 1)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list, 2)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";
  test++;
}

TEST_F(ContactsTest, BEH_MAID_AddContacts) {
  std::vector<maidsafe::mi_contact> mi_list;
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";

  maidsafe::Contact msc(contact_);
  ASSERT_EQ(0, sch_->AddContact(msc.PublicName(), msc.PublicKey(),
               msc.FullName(), msc.OfficePhone(), msc.Birthday(),
               msc.Gender(), msc.Language(), msc.Country(), msc.City(),
               msc.Confirmed(), 0, 0))
            << "MI - Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)1, mi_list.size()) <<
            "List came back empty after addition.";

  maidsafe::mi_contact mic;
  ASSERT_EQ(0, sch_->GetContactInfo(msc.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc.PublicName(), mic.pub_name_) <<
            "MI - Public name not the same";

  ASSERT_EQ(0, sch_->AddContact(msc.PublicName(), msc.PublicKey(),
               msc.FullName(), msc.OfficePhone(), msc.Birthday(),
               msc.Gender(), msc.Language(), msc.Country(), msc.City(),
               msc.Confirmed(), 0, 0))
            << "MI - Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)1, mi_list.size()) <<
            "MI - List came back with wrong number of elements after addition.";

  msc.SetPublicName("palo.feo.smer");
  ASSERT_EQ(0, sch_->AddContact(msc.PublicName(), msc.PublicKey(),
               msc.FullName(), msc.OfficePhone(), msc.Birthday(),
               msc.Gender(), msc.Language(), msc.Country(), msc.City(),
               msc.Confirmed(), 0, 0))
            << "MI - Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)2, mi_list.size()) <<
            "MI - List came back with wrong number of elements after addition.";
}

TEST_F(ContactsTest, BEH_MAID_DeleteContacts) {
  std::vector<maidsafe::mi_contact> mi_list;
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";

  maidsafe::Contact msc(contact_);
  ASSERT_EQ(0, sch_->AddContact(msc.PublicName(), msc.PublicKey(),
               msc.FullName(), msc.OfficePhone(), msc.Birthday(),
               msc.Gender(), msc.Language(), msc.Country(), msc.City(),
               msc.Confirmed(), 0, 0))
            << "MI - Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)1, mi_list.size()) <<
            "MI - List came back empty after addition.";

  maidsafe::mi_contact mic;
  ASSERT_EQ(0, sch_->GetContactInfo(msc.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc.PublicName(), mic.pub_name_) <<
            "MI - Public name not the same";

  ASSERT_EQ(0, sch_->DeleteContact(msc.PublicName())) <<
            "MI - Problem deleting contact.";
  ASSERT_EQ(-1913, sch_->GetContactInfo(msc.PublicName(), &mic)) <<
            "MI - Contact exists after deletion";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "MI - List came back empty after addition.";
  ASSERT_EQ(-1901, sch_->DeleteContact(msc.PublicName())) <<
            "MI - Problem deleting contact.";
}

TEST_F(ContactsTest, BEH_MAID_Update_Select_PubName_Contacts) {
  std::vector<maidsafe::mi_contact> mi_list;
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";

  maidsafe::Contact msc(contact_);
  ASSERT_EQ(0, sch_->AddContact(msc.PublicName(), msc.PublicKey(),
               msc.FullName(), msc.OfficePhone(), msc.Birthday(),
               msc.Gender(), msc.Language(), msc.Country(), msc.City(),
               msc.Confirmed(), 0, 0))
            << "MI - Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)1, mi_list.size()) <<
            "MI - List came back empty after addition.";

  maidsafe::mi_contact mic;
  ASSERT_EQ(0, sch_->GetContactInfo(msc.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc.PublicName(), mic.pub_name_) <<
            "MI - Public name not the same";

  maidsafe::Contact msc1;
  ASSERT_TRUE(msc1.SetPublicName(msc.PublicName())) <<
              "Failed to set public name.";
  ASSERT_TRUE(msc1.SetPublicKey("zyxwvutsrq")) <<
              "Failed to set publick key.";
  ASSERT_TRUE(msc1.SetFullName("Andale Tonto")) << "Failed to set full name.";
  ASSERT_TRUE(msc1.SetOfficePhone("9876543210")) <<
              "Failed to set office phone.";
  ASSERT_TRUE(msc1.SetBirthday("22071983")) << "Failed to set office phone.";
  ASSERT_TRUE(msc1.SetGender('F')) << "Failed to set gender.";
  ASSERT_TRUE(msc1.SetLanguage(22)) << "Failed to set language.";
  ASSERT_TRUE(msc1.SetCountry(7)) << "Failed to set country.";
  ASSERT_TRUE(msc1.SetCity("DF")) << "Failed to set city.";
  ASSERT_TRUE(msc1.SetConfirmed('U')) << "Failed to set confirmation status.";

  // Public key
  ASSERT_EQ(0, sch_->UpdateContactKey(msc1.PublicName(), msc1.PublicKey()))
            << "MI - Pub key update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.PublicName(), mic.pub_name_) <<
            "MI - Public name not the same";

  // Full Name
  ASSERT_EQ(0, sch_->UpdateContactFullName(msc1.PublicName(),
            msc1.FullName())) << "MI - Full Name update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.FullName(), mic.full_name_) <<
            "MI - Full Name not the same";

  // Office Phone
  ASSERT_EQ(0, sch_->UpdateContactOfficePhone(msc1.PublicName(),
            msc1.OfficePhone())) << "MI - Office Phone update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.OfficePhone(), mic.office_phone_) <<
            "MI - Office Phone not the same";

  // Birthday
  ASSERT_EQ(0, sch_->UpdateContactBirthday(msc1.PublicName(),
            msc1.Birthday())) << "MI - Birthday update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.Birthday(), mic.birthday_) <<
            "MI - Birthday not the same";

  // Gender
  ASSERT_EQ(0, sch_->UpdateContactGender(msc1.PublicName(),
            msc1.Gender())) << "MI - Gender update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.Gender(), mic.gender_) <<
            "MI - Gender not the same";

  // Language
  ASSERT_EQ(0, sch_->UpdateContactLanguage(msc1.PublicName(),
            msc1.Language())) << "MI - Language update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.Language(), mic.language_) <<
            "MI - Language not the same";

  // Country
  ASSERT_EQ(0, sch_->UpdateContactCountry(msc1.PublicName(),
            msc1.Country())) << "MI - Country update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.Country(), mic.country_) <<
            "MI - Country not the same";

  // City
  ASSERT_EQ(0, sch_->UpdateContactCity(msc1.PublicName(),
            msc1.City())) << "MI - City update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.City(), mic.city_) <<
            "MI - City not the same";

  // Confirmed
  ASSERT_EQ(0, sch_->UpdateContactConfirmed(msc1.PublicName(),
            msc1.Confirmed())) << "MI - Confirmed update failed";
  ASSERT_EQ(0, sch_->GetContactInfo(msc1.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc1.Confirmed(), mic.confirmed_) <<
            "MI - Confirmed not the same";
}

TEST_F(ContactsTest, BEH_MAID_LastContact_Rank_Contacts) {
  std::string pub_name("");
  std::vector<maidsafe::mi_contact> mi_list;
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
            "List came back not empty after DB creation.";

  maidsafe::Contact msc(contact_);
  ASSERT_EQ(0, sch_->AddContact(msc.PublicName(), msc.PublicKey(),
               msc.FullName(), msc.OfficePhone(), msc.Birthday(),
               msc.Gender(), msc.Language(), msc.Country(), msc.City(),
               msc.Confirmed(), 0, 0))
            << "MI - Problem adding a contact";
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)1, mi_list.size()) <<
            "MI - List came back empty after addition.";

  pub_name = msc.PublicName();
  maidsafe::mi_contact mic;
  ASSERT_EQ(0, sch_->SetLastContactRank(msc.PublicName())) <<
            "Problem modifying contact";
  ASSERT_EQ(0, sch_->GetContactInfo(msc.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc.PublicName(), mic.pub_name_) <<
            "MI - Public name not the same";
  ASSERT_LT(0, mic.last_contact_) <<
            "Last contact did not update";
  boost::uint32_t time = mic.last_contact_;
  ASSERT_EQ(1, mic.rank_) << "Rank did not update";

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, sch_->SetLastContactRank(msc.PublicName())) <<
            "Problem modifying contact";
  ASSERT_EQ(0, sch_->GetContactInfo(msc.PublicName(), &mic)) <<
            "MI - Problem getting the contact";
  ASSERT_EQ(msc.PublicName(), mic.pub_name_) <<
            "MI - Public name not the same";
  ASSERT_LT(time, static_cast<boost::uint32_t>(mic.last_contact_)) <<
            "Last contact did not update";
  ASSERT_EQ(2, mic.rank_) << "Rank did not update";
}

TEST_F(ContactsTest, BEH_MAID_ListContacts_Rank_LastContact) {
  std::vector<maidsafe::mi_contact> mi_list;
  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)0, mi_list.size()) <<
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
    int rt = base::get_epoch_time() - r;
    contact.push_back(base::itos(rt));
    ASSERT_EQ(0, sch_->AddContact(contact[0], contact[1], contact[2],
              contact[3], contact[4], 'M', n, n, contact[8], 'C', 0, 0));
  }

  ASSERT_EQ(0, sch_->GetContactList(&mi_list)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)20, mi_list.size()) <<
            "List came back not empty after DB creation.";

  ASSERT_EQ(0, sch_->GetContactList(&mi_list, 1)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)20, mi_list.size()) <<
            "List came back not empty after DB creation.";

  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    maidsafe::mi_contact mic = mi_list[n];
    maidsafe::mi_contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.rank_, mic1.rank_) << "Rank order higher-to-lower broken.";
  }

  ASSERT_EQ(0, sch_->GetContactList(&mi_list, 2)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)20, mi_list.size()) <<
            "List came back not empty after DB creation.";

  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    maidsafe::mi_contact mic = mi_list[n];
    maidsafe::mi_contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.last_contact_, mic1.last_contact_) <<
              "Last contact order higher-to-lower broken.";
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
    int rt = base::get_epoch_time() - r;
    contact.push_back(base::itos(rt));
    ASSERT_EQ(0, sch_->AddContact(contact[0], contact[1], contact[2],
              contact[3], contact[4], 'M', n, n, contact[8], 'C', 0, 0));
  }

  ASSERT_EQ(0, sch_->GetContactList(&mi_list, 1)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)100, mi_list.size()) <<
            "List came back not empty after DB creation.";

  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    maidsafe::mi_contact mic = mi_list[n];
    maidsafe::mi_contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.rank_, mic1.rank_) << "Rank order higher-to-lower broken.";
  }

  ASSERT_EQ(0, sch_->GetContactList(&mi_list, 2)) <<
            "MI - Problem getting contact list";
  ASSERT_EQ((unsigned)100, mi_list.size()) <<
            "MI - List with wrong size.";

  for (unsigned int n = 0; n < mi_list.size()-1; n++) {
    maidsafe::mi_contact mic = mi_list[n];
    maidsafe::mi_contact mic1 = mi_list[n+1];
    ASSERT_GE(mic.last_contact_, mic1.last_contact_) <<
              "Last contact order higher-to-lower broken.";
  }
}
