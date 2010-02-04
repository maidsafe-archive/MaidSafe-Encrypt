/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Common functions used in tests which have a mock
*               VaultServiceLogic object
* Version:      1.0
* Created:      2010-01-12-16.03.33
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

#include "tests/maidsafe/mockvaultservicelogic.h"

#include <algorithm>

namespace mock_vsl {

void KGroup::MakeAmendAccountRequests(
    const maidsafe::AmendAccountRequest::Amendment &type,
    const std::string &account_pmid,
    const boost::uint64_t &data_size,
    const std::string &chunkname,
    std::vector<maidsafe::AmendAccountRequest> *requests) {
  if (requests == NULL)
    return;
  requests->clear();
  maidsafe::AmendAccountRequest request;
  request.set_amendment_type(type);
  request.set_account_pmid(account_pmid);
  request.set_chunkname(chunkname);
  maidsafe::SignedSize *signed_size = request.mutable_signed_size();
  for (size_t i = 0; i < members_.size(); ++i) {
    signed_size->set_data_size(data_size);
    signed_size->set_signature(co_.AsymSign(base::itos_ull(data_size), "",
        members_.at(i).pmid_private, crypto::STRING_STRING));
    signed_size->set_pmid(members_.at(i).pmid);
    signed_size->set_public_key(members_.at(i).pmid_public);
    signed_size->set_public_key_signature(members_.at(i).pmid_public_signature);
    requests->push_back(request);
  }
}

void CopyResult(const int &response,
                boost::mutex *mutex,
                boost::condition_variable *cv,
                int *result) {
  boost::mutex::scoped_lock lock(*mutex);
  *result = response;
  cv->notify_one();
};

std::string MakeFindNodesResponse(const FindNodesResponseType &type,
                                  std::vector<std::string> *pmids) {
  if (type == kFailParse)
    return "It's not going to parse.";
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string ser_node;
  kad::FindResponse find_response;
  if (type == kResultFail)
    find_response.set_result(kad::kRpcResultFailure);
  else
    find_response.set_result(kad::kRpcResultSuccess);
  int contact_count(kad::K);
  if (type == kTooFewContacts)
    contact_count = 1;
  // Set all IDs close to value of account we're going to be looking for to
  // avoid test node replacing one of these after the kad FindKNodes
  std::string account_owner(co.Hash("Account Owner", "", crypto::STRING_STRING,
      false));
  std::string account_name(co.Hash(account_owner + kAccount, "",
      crypto::STRING_STRING, false));
  char x = 'a';
  for (int i = 0; i < contact_count; ++i, ++x) {
    std::string name = account_name.replace(account_name.size() - 1, 1, 1, x);
    pmids->push_back(name);
    kad::Contact node(name, "192.168.1.1", 5000 + i);
    node.SerialiseToString(&ser_node);
    find_response.add_closest_nodes(ser_node);
  }
  find_response.SerializeToString(&ser_node);
  return ser_node;
};

void RunCallback(const std::string &find_nodes_response,
                 const base::callback_func_type &callback) {
  callback(find_nodes_response);
};

void RunVaultCallback(const maidsafe_vault::ReturnCode &result,
                      const VoidFuncOneInt &callback) {
  callback(result);
}

void DoneRun(const int &min_delay,
             const int &max_delay,
             google::protobuf::Closure* callback) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int diff = max_delay - min;
  if (diff < 1)
    diff = 1;
  int sleep_time(base::random_32bit_uinteger() % diff + min);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  callback->Run();
};

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback) {
  boost::thread(DoneRun, min_delay, max_delay, callback);
};

}  // namespace mock_vsl
