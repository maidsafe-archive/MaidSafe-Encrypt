/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class for handling accounts
* Version:      1.0
* Created:      30/07/2009 18:17:35 PM
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

#ifndef MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_
#define MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_

#include <boost/multi_index_container.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/maidsafe-dht.h>

#include <list>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/sync_data.pb.h"

namespace mi = boost::multi_index;

namespace maidsafe_vault {


struct Account {
  Account(std::string pmid,
          boost::uint64_t offered,
          boost::uint64_t vault_used,
          boost::uint64_t account_used,
          std::list<std::string> alerts)
              : pmid_(pmid),
                offered_(offered),
                vault_used_(vault_used),
                account_used_(account_used),
                alerts_(alerts) {}
  void operator() (const std::string &alert,
                   VaultAccountSet::VaultAccount *vault_account) {
    vault_account->add_alerts(alert);
  }
  std::string pmid_;
  boost::uint64_t offered_;
  boost::uint64_t vault_used_;
  boost::uint64_t account_used_;
  std::list<std::string> alerts_;
};

// Tags
struct account_pmid {};

typedef mi::multi_index_container<
  Account,
  mi::indexed_by<
    mi::ordered_unique<
      mi::tag<account_pmid>,
      BOOST_MULTI_INDEX_MEMBER(Account, std::string, pmid_)
    >
  >
> AccountSet;

class AccountHandler {
 public:
  explicit AccountHandler(bool start_immediately)
      : accounts_(), account_mutex_(), started_(start_immediately) {}
  ~AccountHandler() {}
  void set_started(bool started);
  int HaveAccount(const std::string &pmid);
  int AddAccount(const std::string &pmid, const boost::uint64_t &offer);
  int DeleteAccount(const std::string &pmid);
  int AmendAccount(const std::string &pmid,
                   const int &field,
                   const boost::uint64_t &offer,
                   const bool &increase);
  int GetAccountInfo(const std::string &pmid,
                     boost::uint64_t *offered,
                     boost::uint64_t *vault_used,
                     boost::uint64_t *account_used);
  int GetAlerts(const std::string &pmid, std::list<std::string> *alerts);
  int AddAlerts(const std::string &pmid, const std::string &alert);
  VaultAccountSet PutToPb();
  void GetFromPb(const VaultAccountSet &vault_account_set);
 private:
  AccountHandler(const AccountHandler&);
  AccountHandler& operator=(const AccountHandler&);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerInit);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerAddAndFind);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerModify);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerDelete);
  FRIEND_TEST(AccountHandlerTest, FUNC_VAULT_AccountHandlerDeletePutGetPb);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_ProcessRequest);
  AccountSet accounts_;
  boost::mutex account_mutex_;
  bool started_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_
