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

#include <utility>

namespace maidsafe_vault {

int AccountHandler::HaveAccount(const std::string &pmid) {
  boost::mutex::scoped_lock loch(account_mutex_);
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  return kSuccess;
}

int AccountHandler::AddAccount(const std::string &pmid,
                               const boost::uint64_t &offer) {
  Account row(pmid, offer, 0, 0, std::list<std::string>());
  boost::mutex::scoped_lock loch(account_mutex_);
  std::pair<AccountSet::iterator, bool> sp = accounts_.insert(row);

  if (!sp.second)
    return kAccountExists;
  return kSuccess;
}

int AccountHandler::DeleteAccount(const std::string &pmid) {
  boost::mutex::scoped_lock loch(account_mutex_);
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
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  Account row = *it;
  switch (field) {
    case 1: if (amount < row.vault_used_ || amount < row.account_used_)
              return kAccountNotEnoughSpace;
            row.offered_ = amount;
            break;
    case 2: if (increase) {
              if ((amount + row.vault_used_) > row.offered_)
                return kAccountNotEnoughSpace;
              row.vault_used_ += amount;
            } else {
              if ((row.vault_used_ - amount) > row.vault_used_)
                return kAccountNotEnoughSpace;
              row.vault_used_ -= amount;
            }
            break;
    case 3: if (increase) {
              if ((amount + row.account_used_) > row.offered_)
                return kAccountNotEnoughSpace;
              row.account_used_ += amount;
            } else {
              if ((row.account_used_ - amount) > row.account_used_)
                return kAccountNotEnoughSpace;
              row.account_used_ -= amount;
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
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  *offered = it->offered_;
  *vault_used = it->vault_used_;
  *account_used = it->account_used_;

  return kSuccess;
}

int AccountHandler::GetAlerts(const std::string &pmid,
                              std::list<std::string> *alerts) {
  alerts->clear();
  boost::mutex::scoped_lock loch(account_mutex_);
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  Account row = *it;
  *alerts = row.alerts_;
  row.alerts_.clear();
  accounts_.replace(it, row);

  return kSuccess;
}

int AccountHandler::AddAlerts(const std::string &pmid,
                              const std::string &alert) {
  if (alert.empty())
    return kAccountEmptyAlert;
  boost::mutex::scoped_lock loch(account_mutex_);
  AccountSet::iterator it = accounts_.find(pmid);
  if (it == accounts_.end())
    return kAccountNotFound;

  Account row = *it;
  row.alerts_.push_back(alert);
  accounts_.replace(it, row);

  return kSuccess;
}

}  // namespace maidsafe_vault
