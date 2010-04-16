/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class to handle account amendments
* Version:      1.0
* Created:      2010-01-11-14.58.16
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include "maidsafe/vault/accountamendmenthandler.h"

#include <vector>

#include "maidsafe/vault/accountrepository.h"
#include "maidsafe/vault/vaultservicelogic.h"

namespace maidsafe_vault {

int AccountAmendmentHandler::ProcessRequest(
    const maidsafe::AmendAccountRequest *request,
    maidsafe::AmendAccountResponse *response,
    google::protobuf::Closure *done) {
  // Assumes that response->pmid() has already been set and that
  // request->signed_size() validates
  response->set_result(kNack);
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
    repeated_count = amendments_.count(boost::make_tuple(pmid, field,
        data_size, increase));
  }
  if (total_count >= kMaxAccountAmendments ||
      repeated_count >= kMaxRepeatedAccountAmendments) {
    done->Run();
    return kAmendAccountCountError;
  }
  // If amendment has already been added assess request, else add new amendment
  if (repeated_count != 0) {
    int amendment_status(kAccountAmendmentError);
    bool found(false);
    {
      boost::mutex::scoped_lock lock(amendment_mutex_);
      std::pair<AccountAmendmentSet::iterator,
                AccountAmendmentSet::iterator> it;
      it = amendments_.equal_range(boost::make_tuple(pmid, field, data_size,
                                                     increase));
      while (it.first != it.second) {
        AccountAmendment amendment = (*it.first);
        amendment_status = AssessAmendment(pmid, field, data_size, increase,
            PendingAmending(request, response, done), &amendment);
        if (amendment_status == kAccountAmendmentUpdated) {
          found = true;
          amendments_.replace(it.first, amendment);
          return kSuccess;
        } else if (amendment_status == kAccountAmendmentFinished) {
          found = true;
          amendments_.erase(it.first);
          return kSuccess;
        }
        ++it.first;
      }
    }  // mutex unlocked
    if (!found) {
      AccountAmendment amendment(pmid, field, data_size, increase,
          PendingAmending(request, response, done));
      CreateNewAmendment(amendment);
    }
  } else {
    AccountAmendment amendment(pmid, field, data_size, increase,
        PendingAmending(request, response, done));
    CreateNewAmendment(amendment);
  }
  return kSuccess;
}

int AccountAmendmentHandler::AssessAmendment(const std::string &owner_pmid,
                                             const int &amendment_field,
                                             const boost::uint64_t &offer_size,
                                             const bool &inc,
                                             const PendingAmending &pending,
                                             AccountAmendment *amendment) {
  // amendment_mutex_ should already be locked by function calling this one,
  // but just in case...
  boost::mutex::scoped_try_lock lock(amendment_mutex_);
#ifdef DEBUG
    if (lock.owns_lock())
      printf("In AAH::AssessAmendment, amendment_mutex_ wasn't locked.\n");
#endif
  if (amendment->pmid != owner_pmid ||
      amendment->field != amendment_field ||
      amendment->offer != offer_size ||
      amendment->increase != inc) {
#ifdef DEBUG
    printf("In AAH::AssessAmendment, amendment has incorrect parameters.\n");
#endif
    return kAccountAmendmentNotFound;
  }
  // If we're still waiting for result of FindKNodes, add pending to
  // probable_pendings if it has not already been added
  if (amendment->chunk_info_holders.empty()) {
    std::list<PendingAmending>::iterator probable_it =
        amendment->probable_pendings.begin();
    bool found(false);
    while (probable_it != amendment->probable_pendings.end()) {
      if (*probable_it == pending) {
        found = true;
        break;
      }
      ++probable_it;
    }
    if (!found) {
      amendment->probable_pendings.push_back(pending);
      return kAccountAmendmentUpdated;
    } else {
      return kAccountAmendmentNotFound;
    }
  }
  std::map<std::string, bool>::iterator chunk_info_holders_it =
      amendment->chunk_info_holders.find(pending.request.signed_size().pmid());
  // If Chunk Info holder is not in the map, or has already been accounted for
  if (chunk_info_holders_it == amendment->chunk_info_holders.end() ||
      (*chunk_info_holders_it).second) {
    return kAccountAmendmentNotFound;
  } else {  // Increment success count and add this PendingAmending to list
    (*chunk_info_holders_it).second = true;
    ++amendment->success_count;
    amendment->pendings.push_back(pending);
    if (amendment->success_count >= kKadUpperThreshold) {  // Overall success
      if (amendment->account_amendment_result == kAccountAmendmentPending) {
        // Amend actual account
        amendment->account_amendment_result = account_handler_->AmendAccount(
            owner_pmid, amendment_field, offer_size, inc);
      }
      // Set responses and run callbacks
      std::list<PendingAmending>::iterator pendings_it;
      for (pendings_it = amendment->pendings.begin();
           pendings_it != amendment->pendings.end(); ++pendings_it) {
        if (amendment->account_amendment_result == kSuccess)
          (*pendings_it).response->set_result(kAck);
        else
          (*pendings_it).response->set_result(kNack);
        (*pendings_it).done->Run();
      }
      // Clear all pendings now that they've been run
      amendment->pendings.clear();
    }
    if (amendment->success_count >= amendment->chunk_info_holders.size()) {
      return kAccountAmendmentFinished;
    } else {
      return kAccountAmendmentUpdated;
    }
  }
}

void AccountAmendmentHandler::CreateNewAmendment(
    const AccountAmendment &amendment) {
  {
    boost::mutex::scoped_lock lock(amendment_mutex_);
    std::pair<AmendmentsByTimestamp::iterator, bool> p =
        amendments_.get<by_timestamp>().insert(amendment);
    if (!p.second) {  // amendment exists
#ifdef DEBUG
      printf("In AAH::CreateNewAmendment, already a pending amendment with "
             "these parameters.\n");
#endif
      return;
    }
  }
  vault_service_logic_->kadops()->FindCloseNodes(
      amendment.probable_pendings.front().request.chunkname(),
      boost::bind(&AccountAmendmentHandler::CreateNewAmendmentCallback, this,
                  amendment, _1));
}

void AccountAmendmentHandler::CreateNewAmendmentCallback(
    AccountAmendment amendment,
    std::string find_nodes_response) {
  boost::mutex::scoped_lock lock(amendment_mutex_);
  AmendmentsByTimestamp::iterator it =
      amendments_.get<by_timestamp>().find(amendment);
  if (it == amendments_.get<by_timestamp>().end())
    return;
  AccountAmendment modified_amendment = *it;
  std::vector<kad::Contact> contacts;
  boost::mutex mutex;
  boost::condition_variable cv;
  maidsafe::ReturnCode result(maidsafe::kFindNodesError);
  vault_service_logic_->kadops()->HandleFindCloseNodesResponse(
      find_nodes_response, amendment.account_name, &contacts, &mutex, &cv,
      &result);
  if (result == maidsafe::kSuccess && contacts.size() >=
      size_t(kKadUpperThreshold)) {
    // Populate map of Chunk Info holders
    for (size_t i = 0; i < contacts.size(); ++i) {
      modified_amendment.chunk_info_holders.insert(std::pair<std::string, bool>(
          contacts.at(i).node_id().ToStringDecoded(), false));
    }
    // Update multi-index
    amendments_.get<by_timestamp>().replace(it, modified_amendment);
    // Assess probable (enqueued) requests
    while (!modified_amendment.probable_pendings.empty()) {
      if (AssessAmendment(amendment.pmid, amendment.field, amendment.offer,
          amendment.increase, modified_amendment.probable_pendings.front(),
          &modified_amendment) == kAccountAmendmentNotFound) {
        modified_amendment.probable_pendings.front().response->
            set_result(kNack);
        modified_amendment.probable_pendings.front().done->Run();
      }
      modified_amendment.probable_pendings.pop_front();
    }
    amendments_.get<by_timestamp>().replace(it, modified_amendment);
  } else {
    // Set responses and run callbacks
    while (!modified_amendment.probable_pendings.empty()) {
      modified_amendment.probable_pendings.front().response->set_result(kNack);
      modified_amendment.probable_pendings.front().done->Run();
      modified_amendment.probable_pendings.pop_front();
    }
    amendments_.get<by_timestamp>().erase(it);
  }
}

int AccountAmendmentHandler::CleanUp() {
  int count(0);
  boost::mutex::scoped_lock lock(amendment_mutex_);
  AmendmentsByTimestamp::iterator it = amendments_.get<by_timestamp>().begin();
  while (it != amendments_.get<by_timestamp>().end() &&
         (*it).expiry_time < base::get_epoch_milliseconds()) {
    AccountAmendment amendment = *it;
    while (!amendment.probable_pendings.empty()) {
      amendment.probable_pendings.front().response->set_result(kNack);
      amendment.probable_pendings.front().done->Run();
      amendment.probable_pendings.pop_front();
    }
    while (!amendment.pendings.empty()) {
      amendment.pendings.front().response->set_result(kNack);
      amendment.pendings.front().done->Run();
      amendment.pendings.pop_front();
    }
    it = amendments_.get<by_timestamp>().erase(it);
    ++count;
  }
  return count;
}

}  // namespace maidsafe_vault
