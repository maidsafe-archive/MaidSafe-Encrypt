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
#include <maidsafe/maidsafe-dht.h>

#include <list>
#include <string>

#include "maidsafe/common/maidsafe_service_messages.pb.h"

namespace mi = boost::multi_index;

namespace maidsafe {

namespace vault {

namespace test {
class AccountHandlerTest_BEH_VAULT_Init_Test;
class AccountHandlerTest_BEH_VAULT_AddAndFind_Test;
class AccountHandlerTest_BEH_VAULT_Modify_Test;
class AccountHandlerTest_BEH_VAULT_Delete_Test;
class AccountHandlerTest_FUNC_VAULT_PutGetPb_Test;
class AccountHandlerTest_FUNC_VAULT_PutGetAccount_Test;
class AccountAmendmentHandlerTest_BEH_MAID_ProcessRequest_Test;
}  // namespace test

// TODO(Fraser#5#): 2010-03-29 - Ennumerate and define alert types and struct
//                               Once done, replace following free function
inline void PutAlertToPb(const std::string &alert,
                         VaultAccountSet::VaultAccount *vault_account) {
  vault_account->add_alerts(alert);
}

struct Account {
  Account(std::string pmid,
          boost::uint64_t offered,
          boost::uint64_t vault_used,
          boost::uint64_t account_used,
          std::list<std::string> alerts)
              : pmid(pmid),
                offered(offered),
                vault_used(vault_used),
                account_used(account_used),
                alerts(alerts) {}
  Account(const Account &account)
      : pmid(account.pmid),
        offered(account.offered),
        vault_used(account.vault_used),
        account_used(account.account_used),
        alerts(account.alerts) {}
  explicit Account(const VaultAccountSet::VaultAccount &vault_account)
      : pmid(vault_account.pmid()),
        offered(vault_account.offered()),
        vault_used(vault_account.vault_used()),
        account_used(vault_account.account_used()),
        alerts() {
    for (int i = 0; i < vault_account.alerts_size(); ++i)
      alerts.push_back(vault_account.alerts(i));
  }
  void PutToPb(VaultAccountSet::VaultAccount *vault_account) const {
    vault_account->set_pmid(pmid);
    vault_account->set_offered(offered);
    vault_account->set_vault_used(vault_used);
    vault_account->set_account_used(account_used);
    std::for_each(alerts.begin(), alerts.end(),
        boost::bind(&PutAlertToPb, _1, vault_account));
  }
  std::string pmid;
  boost::uint64_t offered;
  boost::uint64_t vault_used;
  boost::uint64_t account_used;
  std::list<std::string> alerts;
};

// Tags
struct account_pmid {};

typedef mi::multi_index_container<
  Account,
  mi::indexed_by<
    mi::ordered_unique<
      mi::tag<account_pmid>,
      BOOST_MULTI_INDEX_MEMBER(Account, std::string, pmid)
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
  VaultAccountSet PutSetToPb(const std::string &exclude);
  void GetSetFromPb(const VaultAccountSet &vault_account_set);
  int GetAccount(const std::string &pmid, Account *account);
  int InsertAccountFromPb(const VaultAccountSet::VaultAccount &vault_account);
 private:
  AccountHandler(const AccountHandler&);
  AccountHandler& operator=(const AccountHandler&);
  friend class test::AccountHandlerTest_BEH_VAULT_Init_Test;
  friend class test::AccountHandlerTest_BEH_VAULT_AddAndFind_Test;
  friend class test::AccountHandlerTest_BEH_VAULT_Modify_Test;
  friend class test::AccountHandlerTest_BEH_VAULT_Delete_Test;
  friend class test::AccountHandlerTest_FUNC_VAULT_PutGetPb_Test;
  friend class test::AccountHandlerTest_FUNC_VAULT_PutGetAccount_Test;
  friend class test::AccountAmendmentHandlerTest_BEH_MAID_ProcessRequest_Test;
  AccountSet accounts_;
  boost::mutex account_mutex_;
  bool started_;
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_
