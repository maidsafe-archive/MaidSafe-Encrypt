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
  AccountHandler ah;
  ASSERT_EQ(size_t(0), ah.accounts_.size());
}

TEST_F(AccountHandlerTest, BEH_VAULT_AccountHandlerAddAndFind) {
  AccountHandler ah;
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
  AccountHandler ah;
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
  AccountHandler ah;
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

}  // namespace maidsafe_vault
