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


namespace maidsafe_vault {

class AccountHandlerTest : public testing::Test {
 public:
  AccountHandlerTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
};

TEST_F(AccountHandlerTest, BEH_VAULT_AccountHandlerInit) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
}

TEST_F(AccountHandlerTest, BEH_VAULT_AccountHandlerAddAndFind) {
  AccountHandler ah(true);
  ASSERT_EQ(size_t(0), ah.accounts_.size());
  ASSERT_EQ(kAccountNotFound, ah.HaveAccount("AAAAAAAAA"));

  std::string pmid("some pmid");
  boost::uint64_t offer(1234567890);
  ASSERT_EQ(0, ah.AddAccount(pmid, offer));
  ASSERT_EQ(0, ah.HaveAccount(pmid));
  ASSERT_EQ(kAccountExists, ah.AddAccount(pmid, offer));
  ASSERT_EQ(0, ah.HaveAccount(pmid));
  ASSERT_EQ(size_t(1), ah.accounts_.size());
}

TEST_F(AccountHandlerTest, BEH_VAULT_AccountHandlerModify) {
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

  boost::uint64_t offer(1234567890);
  ASSERT_EQ(0, ah.AddAccount(pmid, offer));

  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  offer = 3000;
  ASSERT_EQ(0, ah.AmendAccount(pmid, 1, offer, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(boost::uint64_t(0), vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  boost::uint64_t amount(1500);
  ASSERT_EQ(0, ah.AmendAccount(pmid, 2, amount, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  ASSERT_EQ(kAccountNotEnoughSpace, ah.AmendAccount(pmid, 1, 1000, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  ASSERT_EQ(kAccountNotEnoughSpace, ah.AmendAccount(pmid, 2, 1501, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(0), account_used);

  ASSERT_EQ(0, ah.AmendAccount(pmid, 3, amount, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(amount, account_used);

  ASSERT_EQ(0, ah.AmendAccount(pmid, 3, amount, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(offer, account_used);

  ASSERT_EQ(kAccountNotEnoughSpace, ah.AmendAccount(pmid, 3, 1, true));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(offer, account_used);

  ASSERT_EQ(0, ah.AmendAccount(pmid, 3, 2000, false));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(1000), account_used);

  ASSERT_EQ(kAccountNotEnoughSpace, ah.AmendAccount(pmid, 2, 1501, false));
  ASSERT_EQ(0, ah.GetAccountInfo(pmid, &offered, &vault_space, &account_used));
  ASSERT_EQ(offer, offered);
  ASSERT_EQ(amount, vault_space);
  ASSERT_EQ(boost::uint64_t(1000), account_used);
}

TEST_F(AccountHandlerTest, BEH_VAULT_AccountHandlerDelete) {
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

TEST_F(AccountHandlerTest, FUNC_VAULT_AccountHandlerPutGetPb) {
  AccountHandler account_handler1(true), account_handler2(true);
  std::pair<AccountSet::iterator, bool> result;
  const int kNumEntries(698);
  for (int i = 0; i < kNumEntries; ++i) {
    std::list<std::string> alerts;
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 999); ++j)
      alerts.push_back(base::RandomString(base::RandomUint32() % 999));
    Account account(base::RandomString(64), base::RandomUint32(),
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

TEST_F(AccountHandlerTest, FUNC_VAULT_AccountHandlerPutGetAccount) {
  // Test with account handler not started
  AccountHandler account_handler(false);
  VaultAccountSet::VaultAccount vault_account_put;
  vault_account_put.set_pmid(base::RandomString(64));
  vault_account_put.set_offered(base::RandomUint32());
  vault_account_put.set_vault_used(base::RandomUint32());
  vault_account_put.set_account_used(base::RandomUint32());
  for (boost::uint16_t j = 0; j < (base::RandomUint32() % 999); ++j) {
    vault_account_put.add_alerts(base::RandomString(
        base::RandomUint32() % 999));
  }
  ASSERT_EQ(kAccountHandlerNotStarted,
            account_handler.InsertAccountFromPb(vault_account_put));
  std::list<std::string> alerts;
  alerts.push_back(base::RandomString(base::RandomUint32() % 999));
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
  const size_t kNumEntries(551);
  for (size_t i = 0; i < kNumEntries; ++i) {
    alerts.clear();
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 999); ++j)
      alerts.push_back(base::RandomString(base::RandomUint32() % 999));
    result = account_handler.accounts_.insert(Account(base::RandomString(64),
        base::RandomUint32(), base::RandomUint32(),
        base::RandomUint32(), alerts));
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
      vault_account_put.pmid(), (base::RandomUint32() % 999)));
  ASSERT_EQ(kNumEntries + 1, account_handler.accounts_.size());
}

}  // namespace maidsafe_vault
