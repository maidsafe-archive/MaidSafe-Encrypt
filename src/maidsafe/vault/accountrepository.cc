/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class for manipulating pending store requests
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

int AccountAmendmentHandler::ProcessRequest(
    const maidsafe::AmendAccountRequest *request,
    maidsafe::AmendAccountResponse *response,
    google::protobuf::Closure *done) {
  // Assume that response->pmid() has already been set and that
  // request->signed_size() validates
  response->set_result(kNack);
  // Check we're below limits for amendments and repetitions
  bool increase(false);
  int field(2);
  if (request->amendment_type() ==
      maidsafe::AmendAccountRequest::kSpaceGivenInc ||
      request->amendment_type() ==
      maidsafe::AmendAccountRequest::kSpaceTakenInc)
    increase = true;
  if (request->amendment_type() ==
      maidsafe::AmendAccountRequest::kSpaceTakenDec ||
      request->amendment_type() ==
      maidsafe::AmendAccountRequest::kSpaceTakenInc)
    field = 3;
  // Check that we've got valid amendment type
  if (!increase && field == 2 && request->amendment_type() !=
      maidsafe::AmendAccountRequest::kSpaceGivenDec) {
    done->Run();
    return kAmendAccountTypeError;
  }
  // Check amendment set size is not too large
  std::string pmid(request->account_pmid());
  boost::uint64_t data_size(request->signed_size().data_size());
  size_t total_count(0), repeated_count(0);
  {
    boost::mutex::scoped_lock lock(amendment_mutex_);
    total_count = amendments_.size();
    repeated_count = amendments_.get<1>().count(boost::make_tuple(pmid, field,
        data_size, increase));
  }
  if (total_count >= kMaxAccountAmendments ||
      repeated_count >= kMaxRepeatedAccountAmendments) {
    done->Run();
    return kAmendAccountCountError;
  }
  // If amendment has already been added assess request, else add new amendment
  if (repeated_count != 0) {
//    while not found
//      for each matching amendment
//        "assess amendment" (checks for overall success/failure and if so
//           sets all pending responses & calls all pending done runs & deletes all these
//           & returns found_but_not_yet_decided, not_found, found_and_overall_success, found_and_overall_failure)
//    after while, if still not found, add new amendment, start knode find nodes as below
  } else {
//    add new amendment
//    start knode findnodes
//    calls back to function which "assess amendment"
  }




  int result = account_handler_->AmendAccount(pmid, field, data_size, increase);
  if (result != kSuccess) {
    done->Run();
    return result;
  } else {
    response->set_result(kAck);
    done->Run();
    return kSuccess;
  }
}

void AccountAmendmentHandler::CleanUp() {
}

}  // namespace maidsafe_vault
