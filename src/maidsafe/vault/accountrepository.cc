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

#include "maidsafe/vault/accountrepository.h"

#include <algorithm>
#include <utility>

namespace maidsafe_vault {

void AccountHandler::set_started(bool started) {
  boost::mutex::scoped_lock lock(account_mutex_);
  started_ = started;
}

int AccountHandler::HaveAccount(const std::string &pmid) {
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  return kSuccess;
}

int AccountHandler::AddAccount(const std::string &pmid,
                               const boost::uint64_t &offer) {
  Account row(pmid, offer, 0, 0, std::list<std::string>());
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  std::pair<AccountSet::iterator, bool> sp = accounts_.insert(row);

  if (!sp.second)
    return kAccountExists;
  return kSuccess;
}

int AccountHandler::DeleteAccount(const std::string &pmid) {
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  accounts_.erase(pmid);
  it = accounts_.find(pmid);
  if (it != accounts_.end())
    return kAccountDeleteFailed;
  return kSuccess;
}

int AccountHandler::AmendAccount(const std::string &pmid, const int &field,
                                 const boost::uint64_t &amount,
                                 const bool &increase) {
  if (field < 1 || field > 3)
    return kAccountWrongAccountField;
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  Account row = *it;
  switch (field) {
    case 1: if (amount < row.vault_used || amount < row.account_used)
              return kAccountInvalidAmount;
            row.offered = amount;
            break;
    case 2: if (increase) {  // increment space given
              if (row.vault_used + amount > row.offered)
                return kAccountNotEnoughSpace;
              row.vault_used += amount;
            } else {  // decrement space given
              if (amount > row.vault_used)
                return kAccountInvalidAmount;
              row.vault_used -= amount;
            }
            break;
    case 3: if (increase) {  // increment space taken
              if (row.account_used + amount > row.offered)
                return kAccountNotEnoughSpace;
              row.account_used += amount;
            } else {  // decrement space taken
              if (amount > row.account_used)
                return kAccountInvalidAmount;
              row.account_used -= amount;
            }
            break;
  }
  accounts_.replace(it, row);

  return kSuccess;
}

int AccountHandler::GetAccountInfo(const std::string &pmid,
                                   boost::uint64_t *offered,
                                   boost::uint64_t *vault_used,
                                   boost::uint64_t *account_used) {
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  *offered = it->offered;
  *vault_used = it->vault_used;
  *account_used = it->account_used;

  return kSuccess;
}

int AccountHandler::GetAlerts(const std::string &pmid,
                              std::list<std::string> *alerts) {
  alerts->clear();
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  Account row = *it;
  *alerts = row.alerts;
  row.alerts.clear();
  accounts_.replace(it, row);

  return kSuccess;
}

int AccountHandler::AddAlerts(const std::string &pmid,
                              const std::string &alert) {
  if (alert.empty())
    return kAccountEmptyAlert;
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  Account row = *it;
  row.alerts.push_back(alert);
  accounts_.replace(it, row);

  return kSuccess;
}

VaultAccountSet AccountHandler::PutSetToPb(const std::string &exclude) {
  VaultAccountSet vault_account_set;
  {
    boost::mutex::scoped_lock loch(account_mutex_);
    for (AccountSet::iterator it = accounts_.begin();
         it != accounts_.end(); ++it) {
      if (it->pmid != exclude) {
        VaultAccountSet::VaultAccount *vault_account =
            vault_account_set.add_vault_account();
        it->PutToPb(vault_account);
      }
    }
  }
  return vault_account_set;
}

void AccountHandler::GetSetFromPb(const VaultAccountSet &vault_account_set) {
  VaultAccountSet::VaultAccount vault_account;
  std::list<std::string> alerts;
  boost::mutex::scoped_lock loch(account_mutex_);
  for (int i = 0; i < vault_account_set.vault_account_size(); ++i) {
    vault_account.Clear();
    vault_account = vault_account_set.vault_account(i);
    alerts.clear();
    for (int j = 0; j < vault_account.alerts_size(); ++j)
      alerts.push_back(vault_account.alerts(j));
    Account row(vault_account.pmid(), vault_account.offered(),
        vault_account.vault_used(), vault_account.account_used(), alerts);
    accounts_.insert(row);
  }
  started_ = true;
}

int AccountHandler::GetAccount(const std::string &pmid,
                               Account *account) {
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_) {
    *account = Account("", 0, 0, 0, std::list<std::string>());
    return kAccountHandlerNotStarted;
  }
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end()) {
    *account = Account("", 0, 0, 0, std::list<std::string>());
    return kAccountNotFound;
  } else {
    *account = *it;
    return kSuccess;
  }
}

int AccountHandler::InsertAccountFromPb(
    const VaultAccountSet::VaultAccount &vault_account) {
  Account account(vault_account);
  boost::mutex::scoped_lock loch(account_mutex_);
  if (!started_)
    return kAccountHandlerNotStarted;
  std::pair<AccountSet::iterator, bool> sp = accounts_.insert(account);
  if (!sp.second)
    return kAccountExists;
  return kSuccess;
}

}  // namespace maidsafe_vault
