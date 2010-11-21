/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe contacts
* Version:      1.0
* Created:      2009-01-28-23.19.56
* Revision:     none
* Compiler:     gcc
* Author:       Team maidsafe.net
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
#include "maidsafe/vault/accountrepository.h"
#include "maidsafe/vault/vaultconfig.h"


namespace maidsafe {

namespace vault {

namespace test {

class AccountHandlerTest : public testing::Test {
 public:
  AccountHandlerTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
};

TEST_F(AccountHandlerTest, BEH_VAULT_Init) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
}

TEST_F(AccountHandlerTest, BEH_VAULT_AddAndFind) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
  ASSERT_EQ(kAccountNotFound, ah.HaveAccount("AAAAAAAAA"));

  std::string pmid("some pmid");
  boost::uint64_t offer(1234567890);
  ASSERT_EQ(kSuccess, ah.AddAccount(pmid, offer));
  ASSERT_EQ(kSuccess, ah.HaveAccount(pmid));
  ASSERT_EQ(kAccountExists, ah.AddAccount(pmid, offer));
  ASSERT_EQ(kSuccess, ah.HaveAccount(pmid));
  ASSERT_EQ(size_t(1), ah.accounts_.size());
}

TEST_F(AccountHandlerTest, BEH_VAULT_Modify) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
  std::string pmid("some pmid");
  boost::uint64_t offered(0), vault_space(0), account_used(0);
  ASSERT_EQ(kAccountNotFound, ah.AmendAccount(pmid, 1, 0, true));
  ASSERT_EQ(kAccountNotFound, ah.AmendAccount(pmid, 2, 0, true));
  ASSERT_EQ(kAccountNotFound, ah.AmendAccount(pmid, 3, 0, true));
  ASSERT_EQ(kAccountWrongAccountField, ah.AmendAccount(pmid, 0, 0, true));
  ASSERT_EQ(kAccountWrongAccountField, ah.AmendAccount(pmid, 4, 0, true));
  ASSERT_EQ(kAccountNotFound, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                                &account_used));

  // create account
  boost::uint64_t offer(1234567890);
  ASSERT_EQ(kSuccess, ah.AddAccount(pmid, offer));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  // amend space offered
  offer = 3000;
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 1, offer, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  // increment space given
  boost::uint64_t amount(1500);
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 2, amount, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  // try to reduce space offered to below what's already given
  ASSERT_EQ(kAccountInvalidAmount, ah.AmendAccount(pmid, 1, amount - 10, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  // try to give more space than remaining in offer
  ASSERT_EQ(kAccountNotEnoughSpace, ah.AmendAccount(pmid, 2, 1501, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  // increment space taken
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 3, amount, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(amount, account_used);

  // increment space taken again, no space remains
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 3, amount, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(offer, account_used);

  // try to take even more space
  ASSERT_EQ(kAccountNotEnoughSpace, ah.AmendAccount(pmid, 3, 1, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(offer, account_used);

  // try to reduce space given, amount too high
  ASSERT_EQ(kAccountInvalidAmount, ah.AmendAccount(pmid, 2, amount + 1, false));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(offer, account_used);

  // decrement space given to zero
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 2, amount, false));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(offer, account_used);

  // try to decrement space given again
  ASSERT_EQ(kAccountInvalidAmount, ah.AmendAccount(pmid, 2, 1, false));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(offer, account_used);

  // try to reduce space offered to below what's already taken
  ASSERT_EQ(kAccountInvalidAmount, ah.AmendAccount(pmid, 1, offer - 10, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(offer, account_used);

  // decrement space taken
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 3, offer - 10, false));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(10), account_used);

  // try to decrement space taken by too much
  ASSERT_EQ(kAccountInvalidAmount, ah.AmendAccount(pmid, 3, 20, false));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(10), account_used);

  // set everything to zero
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 3, 10, false));
  ASSERT_EQ(kSuccess, ah.AmendAccount(pmid, 1, 0, true));
  ASSERT_EQ(kSuccess, ah.GetAccountInfo(pmid, &offered, &vault_space,
                                        &account_used));
  ASSERT_EQ(boost::uint64_t(0), offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);
}

TEST_F(AccountHandlerTest, BEH_VAULT_Delete) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
  std::string pmid("some pmid");
  boost::uint64_t offer(1234567890);
  ASSERT_EQ(kAccountNotFound, ah.DeleteAccount(pmid));
  ASSERT_EQ(0, ah.AddAccount(pmid, offer));

  boost::uint64_t offered(0), vault_space(0), account_used(0);
  ASSERT_EQ(0, ah.HaveAccount(pmid));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));

  ASSERT_EQ(0, ah.DeleteAccount(pmid));
  ASSERT_EQ(kAccountNotFound, ah.HaveAccount(pmid));
  ASSERT_EQ(kAccountNotFound, ah.DeleteAccount(pmid));
}

TEST_F(AccountHandlerTest, FUNC_VAULT_PutGetPb) {
  AccountHandler account_handler1(true), account_handler2(true);
  std::pair<AccountSet::iterator, bool> result;
  const int kNumEntries(23);
  for (int i = 0; i < kNumEntries; ++i) {
    std::list<std::string> alerts;
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 9); ++j)
      alerts.push_back(base::RandomAlphaNumericString(
          base::RandomUint32() % 99));
    Account account(base::RandomAlphaNumericString(64), base::RandomUint32(),
        base::RandomUint32(), base::RandomUint32(), alerts);
    result = account_handler1.accounts_.insert(account);
    ASSERT_TRUE(result.second);
  }
  VaultAccountSet vault_account_set = account_handler1.PutSetToPb("");
  std::string serialised_vault_account_set1;
  ASSERT_TRUE(vault_account_set.SerializeToString(
      &serialised_vault_account_set1));
  vault_account_set.Clear();
  ASSERT_TRUE(vault_account_set.ParseFromString(serialised_vault_account_set1));
  account_handler2.GetSetFromPb(vault_account_set);
  ASSERT_EQ(account_handler1.accounts_.size(),
            account_handler2.accounts_.size());
  AccountSet::iterator it1 = account_handler1.accounts_.begin();
  AccountSet::iterator it2 = account_handler2.accounts_.begin();
  for (; it1 != account_handler1.accounts_.end(); ++it1, ++it2) {
    Account account1(*it1), account2(*it2);
    ASSERT_EQ(account1.pmid, account2.pmid);
    ASSERT_EQ(account1.offered, account2.offered);
    ASSERT_EQ(account1.vault_used, account2.vault_used);
    ASSERT_EQ(account1.account_used, account2.account_used);
    ASSERT_EQ(account1.alerts.size(), account2.alerts.size());
    std::list<std::string>::iterator alerts_it1 = account1.alerts.begin();
    std::list<std::string>::iterator alerts_it2 = account2.alerts.begin();
    for (; alerts_it1 != account1.alerts.end(); ++alerts_it1, ++alerts_it2)
      ASSERT_EQ(*alerts_it1, *alerts_it2);
  }
  vault_account_set.Clear();
  vault_account_set = account_handler1.PutSetToPb("");
  std::string serialised_vault_account_set2;
  ASSERT_TRUE(vault_account_set.SerializeToString(
      &serialised_vault_account_set2));
  ASSERT_EQ(serialised_vault_account_set1, serialised_vault_account_set2);
}

TEST_F(AccountHandlerTest, FUNC_VAULT_PutGetAccount) {
  // Test with account handler not started
  AccountHandler account_handler(false);
  VaultAccountSet::VaultAccount vault_account_put;
  vault_account_put.set_pmid(base::RandomAlphaNumericString(64));
  vault_account_put.set_offered(base::RandomUint32());
  vault_account_put.set_vault_used(base::RandomUint32());
  vault_account_put.set_account_used(base::RandomUint32());
  for (boost::uint16_t j = 0; j < (base::RandomUint32() % 9); ++j) {
    vault_account_put.add_alerts(base::RandomAlphaNumericString(
        base::RandomUint32() % 99));
  }
  ASSERT_EQ(kAccountHandlerNotStarted,
            account_handler.InsertAccountFromPb(vault_account_put));
  std::list<std::string> alerts;
  alerts.push_back(base::RandomAlphaNumericString(base::RandomUint32() % 99));
  Account dummy_account("Not empty", 10, 9, 8, alerts);
  Account account(dummy_account);
  ASSERT_EQ(kAccountHandlerNotStarted,
            account_handler.GetAccount(vault_account_put.pmid(), &account));
  ASSERT_TRUE(account.pmid.empty());
  ASSERT_EQ(boost::uint64_t(0), account.offered);
  ASSERT_EQ(boost::uint64_t(0), account.vault_used);
  ASSERT_EQ(boost::uint64_t(0), account.account_used);
  ASSERT_TRUE(account.alerts.empty());
  account_handler.set_started(true);
  ASSERT_EQ(kAccountNotFound,
            account_handler.HaveAccount(vault_account_put.pmid()));

  // Test before adding account
  account = dummy_account;
  ASSERT_EQ(kAccountNotFound,
            account_handler.GetAccount(vault_account_put.pmid(), &account));
  ASSERT_TRUE(account.pmid.empty());
  ASSERT_EQ(boost::uint64_t(0), account.offered);
  ASSERT_EQ(boost::uint64_t(0), account.vault_used);
  ASSERT_EQ(boost::uint64_t(0), account.account_used);
  ASSERT_TRUE(account.alerts.empty());

  // Add accounts
  std::pair<AccountSet::iterator, bool> result;
  const size_t kNumEntries(42);
  for (size_t i = 0; i < kNumEntries; ++i) {
    alerts.clear();
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 9); ++j)
      alerts.push_back(base::RandomAlphaNumericString(
          base::RandomUint32() % 99));
    result = account_handler.accounts_.insert(Account(
        base::RandomAlphaNumericString(64), base::RandomUint32(),
        base::RandomUint32(), base::RandomUint32(), alerts));
    ASSERT_TRUE(result.second);
  }

  // Insert and retrieve account
  ASSERT_EQ(kSuccess, account_handler.InsertAccountFromPb(vault_account_put));
  ASSERT_EQ(kNumEntries + 1, account_handler.accounts_.size());
  ASSERT_EQ(kSuccess, account_handler.HaveAccount(vault_account_put.pmid()));
  account = dummy_account;
  ASSERT_EQ(kSuccess,
            account_handler.GetAccount(vault_account_put.pmid(), &account));
  ASSERT_EQ(vault_account_put.pmid(), account.pmid);
  ASSERT_EQ(vault_account_put.offered(), account.offered);
  ASSERT_EQ(vault_account_put.vault_used(), account.vault_used);
  ASSERT_EQ(vault_account_put.account_used(), account.account_used);
  ASSERT_EQ(static_cast<size_t>(vault_account_put.alerts_size()),
            account.alerts.size());
  std::list<std::string>::iterator it = account.alerts.begin();
  for (int i = 0; it != account.alerts.end(); ++it, ++i)
    ASSERT_EQ(vault_account_put.alerts(i), *it);

  // Convert account to protocol buffer
  VaultAccountSet::VaultAccount vault_account_get;
  account.PutToPb(&vault_account_get);
  ASSERT_EQ(vault_account_put.pmid(), vault_account_get.pmid());
  ASSERT_EQ(vault_account_put.offered(), vault_account_get.offered());
  ASSERT_EQ(vault_account_put.vault_used(), vault_account_get.vault_used());
  ASSERT_EQ(vault_account_put.account_used(), vault_account_get.account_used());
  ASSERT_EQ(vault_account_put.alerts_size(), vault_account_get.alerts_size());
  for (int i = 0; i < vault_account_put.alerts_size(); ++i)
    ASSERT_EQ(vault_account_put.alerts(i), vault_account_get.alerts(i));

  // Check account can't be added again
  ASSERT_EQ(kAccountExists,
            account_handler.InsertAccountFromPb(vault_account_put));
  ASSERT_EQ(kNumEntries + 1, account_handler.accounts_.size());
  ASSERT_EQ(kAccountExists, account_handler.AddAccount(
      vault_account_put.pmid(), (base::RandomUint32() % 99)));
  ASSERT_EQ(kNumEntries + 1, account_handler.accounts_.size());
}

TEST_F(AccountHandlerTest, BEH_VAULT_AccountHandlerClear) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
  boost::uint32_t n(base::RandomUint32() % 50 + 50);
  for (boost::uint32_t i = 0; i < n; ++i)
    ASSERT_EQ(kSuccess, ah.AddAccount("pmid" + base::IntToString(i), 1234));
  ASSERT_EQ(size_t(n), ah.accounts_.size());
  ah.Clear();
  ASSERT_EQ(size_t(0), ah.accounts_.size());
}

}  // namespace test

}  // namespace vault

}  // namespace maidsafe

