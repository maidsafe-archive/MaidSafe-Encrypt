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

#include "maidsafe/vault/tests/mockvaultservicelogic.h"

#include <boost/lexical_cast.hpp>

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
    signed_size->set_signature(
        maidsafe::RSASign(boost::lexical_cast<std::string>(data_size),
                          members_.at(i).pmid_private));
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
}

void RunVaultCallback(const maidsafe::vault::VaultReturnCode &result,
                      const maidsafe::vault::VoidFuncOneInt &callback) {
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
  int sleep_time(base::RandomUint32() % diff + min);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  callback->Run();
}

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback) {
  boost::thread(DoneRun, min_delay, max_delay, callback);
}

}  // namespace mock_vsl
