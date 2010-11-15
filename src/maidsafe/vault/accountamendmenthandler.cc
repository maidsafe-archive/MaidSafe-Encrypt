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

#include "maidsafe/common/kadops.h"
#include "maidsafe/vault/accountrepository.h"
#include "maidsafe/vault/requestexpectationhandler.h"
#include "maidsafe/vault/vaultservicelogic.h"

namespace maidsafe {

namespace vault {

int AccountAmendmentHandler::ProcessRequest(const AmendAccountRequest *request,
                                            AmendAccountResponse *response,
                                            google::protobuf::Closure *done) {
  // Assumes that response->pmid() has already been set and that
  // request->signed_size() validates
  response->set_result(kNack);
  AmendAccountRequest::Amendment amendment_type = request->amendment_type();
  bool increase(false);
  int field(2);
  if (amendment_type == AmendAccountRequest::kSpaceGivenInc ||
      amendment_type == AmendAccountRequest::kSpaceTakenInc)
    increase = true;
  if (amendment_type == AmendAccountRequest::kSpaceTakenDec ||
      amendment_type == AmendAccountRequest::kSpaceTakenInc)
    field = 3;

  // Check that we've got valid amendment type
  if (!increase && field == 2 && amendment_type !=
      AmendAccountRequest::kSpaceGivenDec) {
    done->Run();
    return kAmendAccountTypeError;
  }

  // Check amendment set size is not too large
  std::string pmid(request->account_pmid());
  std::string chunkname(request->has_chunkname() ? request->chunkname() : "");
  boost::uint64_t data_size(request->signed_size().data_size());
  size_t total_count(0), repeated_count(0);
  {
    boost::mutex::scoped_lock lock(amendment_mutex_);
    total_count = amendments_.size();
    repeated_count = amendments_.count(boost::make_tuple(pmid, field,
        data_size, increase));
  }

  bool tried_cleanup(false);
  while (total_count >= kMaxAccountAmendments ||
         repeated_count >= kMaxRepeatedAccountAmendments) {
    if (!tried_cleanup) {
      if (CleanUp() != 0) {  // i.e. some deletions were made
        boost::mutex::scoped_lock lock(amendment_mutex_);
        total_count = amendments_.size();
        repeated_count = amendments_.count(boost::make_tuple(pmid, field,
            data_size, increase));
      }
      tried_cleanup = true;
    } else {
      done->Run();
      return kAmendAccountCountError;
    }
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
        amendment_status = AssessAmendment(pmid, chunkname, amendment_type,
            field, data_size, increase, PendingAmending(request, response,
            done), &amendment);
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
      AccountAmendment amendment(pmid, chunkname, amendment_type, field,
          data_size, increase, PendingAmending(request, response, done));
      CreateNewAmendment(amendment);
    }
  } else {
    AccountAmendment amendment(pmid, chunkname, amendment_type, field,
        data_size, increase, PendingAmending(request, response, done));
    CreateNewAmendment(amendment);
  }
  return kSuccess;
}

int AccountAmendmentHandler::AssessAmendment(
    const std::string &owner_pmid,
    const std::string &chunkname,
    const AmendAccountRequest::Amendment &amendment_type,
    const int &amendment_field,
    const boost::uint64_t &offer_size,
    const bool &inc,
    PendingAmending pending,
    AccountAmendment *amendment) {
  // amendment_mutex_ should already be locked by function calling this one,
  // but just in case...
  boost::mutex::scoped_try_lock lock(amendment_mutex_);
#ifdef DEBUG
  if (lock.owns_lock())
    printf("In AAH::AssessAmendment, amendment_mutex_ wasn't locked.\n");
#endif
  if (amendment->pmid != owner_pmid ||
      amendment->chunkname != chunkname ||
      amendment->amendment_type != amendment_type ||
      amendment->field != amendment_field ||
      amendment->offer != offer_size ||
      amendment->increase != inc) {
#ifdef DEBUG
    printf("In AAH::AssessAmendment, amendment has incorrect parameters.\n");
#endif
    return kAccountAmendmentNotFound;
  }

  if (account_handler_->HaveAccount(owner_pmid) == kAccountNotFound) {
#ifdef DEBUG
    printf("In AAH::AssessAmendment, handling amendment for non-existing "
           "account (%s).\n", HexSubstr(owner_pmid).c_str());
#endif
    // respond immediately
    if (!pending.responded) {
      pending.response->set_result(kNack);
      pending.responded = true;
      pending.done->Run();
    }
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
    if (amendment->success_count >= kUpperThreshold_) {  // Overall success
      if (amendment->account_amendment_result == kAccountAmendmentPending) {
        // Amend actual account
        amendment->account_amendment_result = account_handler_->AmendAccount(
            owner_pmid, amendment_field, offer_size, inc);
      }

      if (!chunkname.empty())
        amendment_results_.push_back(
            AmendmentResult(owner_pmid, chunkname, amendment_type,
            amendment->account_amendment_result == kSuccess ? kAck : kNack));

      // Set responses and run callbacks
      std::list<PendingAmending>::iterator pendings_it;
      for (pendings_it = amendment->pendings.begin();
           pendings_it != amendment->pendings.end(); ++pendings_it) {
        if (amendment->account_amendment_result == kSuccess)
          (*pendings_it).response->set_result(kAck);
        else
          (*pendings_it).response->set_result(kNack);
        if (!(*pendings_it).responded) {
          (*pendings_it).responded = true;
          (*pendings_it).done->Run();
        } else if (amendment->account_amendment_result == kSuccess) {
#ifdef DEBUG
          printf("In AAH::AssessAmendment, can't send positive response for "
                 "account (%s) amendment!\n", HexSubstr(owner_pmid).c_str());
#endif
        }
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

void AccountAmendmentHandler::FetchAmendmentResults(
    const std::string &owner_name,
    AccountStatusResponse *response) {
  boost::mutex::scoped_lock lock(amendment_mutex_);
  std::list<AmendmentResult>::iterator it = amendment_results_.begin();
  while (it != amendment_results_.end()) {
    if (it->owner_name == owner_name) {
      AccountStatusResponse::AmendmentResult *amendment_result =
          response->add_amendment_results();
      amendment_result->set_amendment_type(it->amendment_type);
      amendment_result->set_chunkname(it->chunkname);
      amendment_result->set_result(it->result);
      it = amendment_results_.erase(it);
    } else {
      ++it;
    }
  }
}

void AccountAmendmentHandler::CreateNewAmendment(AccountAmendment amendment) {
  std::vector<std::string> account_holders_ids =
      request_expectation_handler_->GetExpectedCallersIds(
          amendment.probable_pendings.front().request);
  bool lookup_required(false);
  if (account_holders_ids.size() >= kUpperThreshold_) {
    // Populate map of Chunk Info holders
    for (size_t i = 0; i < account_holders_ids.size(); ++i) {
      amendment.chunk_info_holders.insert(
          std::pair<std::string, bool>(account_holders_ids.at(i), false));
    }
    // Assess probable (enqueued) requests
    while (!amendment.probable_pendings.empty()) {
      boost::mutex::scoped_lock lock(amendment_mutex_);
      AssessAmendment(amendment.pmid, amendment.chunkname,
                      amendment.amendment_type, amendment.field,
                      amendment.offer, amendment.increase,
                      amendment.probable_pendings.front(), &amendment);
      amendment.probable_pendings.pop_front();
    }
  } else {
    lookup_required = true;
  }
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
  if (lookup_required) {
    vault_service_logic_->kadops()->FindKClosestNodes(
        amendment.probable_pendings.front().request.chunkname(),
        boost::bind(&AccountAmendmentHandler::CreateNewAmendmentCallback, this,
                    amendment, _1, _2));
  }
}

void AccountAmendmentHandler::CreateNewAmendmentCallback(
    AccountAmendment amendment,
    const maidsafe::ReturnCode &result,
    const std::vector<kad::Contact> &closest_nodes) {
  boost::mutex::scoped_lock lock(amendment_mutex_);
  AmendmentsByTimestamp::iterator it =
      amendments_.get<by_timestamp>().find(amendment);
  if (it == amendments_.get<by_timestamp>().end())
    return;
  AccountAmendment modified_amendment = *it;
  if (result == kSuccess && closest_nodes.size() >= size_t(kUpperThreshold_)) {
    // Populate map of Chunk Info holders
    for (size_t i = 0; i < closest_nodes.size(); ++i) {
      modified_amendment.chunk_info_holders.insert(std::pair<std::string, bool>(
          closest_nodes.at(i).node_id().String(), false));
    }
    // Update multi-index
    amendments_.get<by_timestamp>().replace(it, modified_amendment);
    // Assess probable (enqueued) requests
    int amendment_status(kAccountAmendmentError);
    while (!modified_amendment.probable_pendings.empty()) {
      amendment_status =
          AssessAmendment(amendment.pmid, amendment.chunkname,
                          amendment.amendment_type, amendment.field,
                          amendment.offer, amendment.increase,
                          modified_amendment.probable_pendings.front(),
                          &modified_amendment);
      modified_amendment.probable_pendings.pop_front();
    }
    amendments_.get<by_timestamp>().replace(it, modified_amendment);
  } else {
    // Set responses and run callbacks
    amendments_.get<by_timestamp>().erase(it);
    while (!modified_amendment.probable_pendings.empty()) {
      if (!modified_amendment.probable_pendings.front().responded) {
        modified_amendment.probable_pendings.front().response->
            set_result(kNack);
        modified_amendment.probable_pendings.front().responded = true;
        modified_amendment.probable_pendings.front().done->Run();
      }
      modified_amendment.probable_pendings.pop_front();
    }
  }
}

int AccountAmendmentHandler::CleanUp() {
  int count(0);
  boost::mutex::scoped_lock lock(amendment_mutex_);
  {
    AmendmentsByTimestamp::iterator it =
        amendments_.get<by_timestamp>().begin();
    while (it != amendments_.get<by_timestamp>().end() &&
          (*it).expiry_time < base::GetEpochMilliseconds()) {
      AccountAmendment amendment = *it;
      while (!amendment.probable_pendings.empty()) {
        if (!amendment.probable_pendings.front().responded) {
          amendment.probable_pendings.front().response->set_result(kNack);
          amendment.probable_pendings.front().responded = true;
          amendment.probable_pendings.front().done->Run();
        }
        amendment.probable_pendings.pop_front();
      }
      while (!amendment.pendings.empty()) {
        if (!amendment.probable_pendings.front().responded) {
          amendment.pendings.front().response->set_result(kNack);
          amendment.pendings.front().responded = true;
          amendment.pendings.front().done->Run();
        }
        amendment.pendings.pop_front();
      }
      it = amendments_.get<by_timestamp>().erase(it);
      ++count;
    }
  }
  {
    std::list<AmendmentResult>::iterator it = amendment_results_.begin();
    while (it != amendment_results_.end()) {
      if (it->expiry_time < base::GetEpochTime()) {
        it = amendment_results_.erase(it);
      } else {
        ++it;
      }
    }
  }
  return count;
}

}  // namespace vault

}  // namespace maidsafe
