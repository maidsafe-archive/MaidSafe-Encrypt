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

#ifndef MAIDSAFE_VAULT_ACCOUNTAMENDMENTHANDLER_H_
#define MAIDSAFE_VAULT_ACCOUNTAMENDMENTHANDLER_H_

#include <boost/multi_index_container.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/maidsafe-dht.h>

#include <list>
#include <map>
#include <string>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace mi = boost::multi_index;

namespace maidsafe_vault {

class AccountHandler;
class VaultServiceLogic;

struct PendingAmending {
  PendingAmending(const maidsafe::AmendAccountRequest *req,
                  maidsafe::AmendAccountResponse *resp,
                  google::protobuf::Closure *cb)
      : request(req), response(resp), done(cb) {}
  ~PendingAmending() {}
  const maidsafe::AmendAccountRequest *request;
  maidsafe::AmendAccountResponse *response;
  google::protobuf::Closure *done;
  bool operator==(const PendingAmending &other) const {
    return (request == other.request &&
            response == other.response &&
            done == other.done);
  }
  bool operator!=(const PendingAmending &other) const {
    return !(*this == other);
  }
};

struct AccountAmendment {
  AccountAmendment(const std::string &owner_pmid,
                   const int &amendment_field,
                   const boost::uint64_t &offer_amount,
                   const bool &inc,
                   const PendingAmending &pending)
      : pmid(owner_pmid),
        field(amendment_field),
        offer(offer_amount),
        increase(inc),
        account_name(),
        chunk_info_holders(),
        pendings(),
        probable_pendings(),
        expiry_time(base::get_epoch_milliseconds() + kAccountAmendmentTimeout),
        success_count(0),
        account_amendment_result(kAccountAmendmentPending) {
    // Add to probable pendings list so that further similar requests don't get
    // added to probable while we're waiting for FindKNodes to return
    probable_pendings.push_back(pending);
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    account_name = co.Hash(pmid + kAccount, "", crypto::STRING_STRING, false);
  }
  bool operator<(const AccountAmendment &aa) const {
    return expiry_time < aa.expiry_time;
  }
  std::string pmid;
  int field;
  boost::uint64_t offer;
  bool increase;
  std::string account_name;
  // Chunk Info holders IDs and flag whether we've received their request
  std::map<std::string, bool> chunk_info_holders;
  // Responses and callbacks awaiting overall success / failure before being run
  std::list<PendingAmending> pendings;
  // Probable pendings awaiting FindKNodes result before being moved to pendings
  std::list<PendingAmending> probable_pendings;
  boost::uint64_t expiry_time;
  boost::uint16_t success_count;
  // Result of attempt to amend the account in the AccountHandler
  int account_amendment_result;
};

// tags
struct by_pmid {};
struct by_timestamp {};

typedef mi::multi_index_container<
  AccountAmendment,
  mi::indexed_by<
    mi::ordered_non_unique<
      mi::tag<by_pmid>,
      mi::composite_key <
        AccountAmendment,
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, std::string, pmid),
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, int, field),
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, boost::uint64_t, offer),
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, bool, increase)
      >
    >,
    mi::ordered_unique< mi::tag<by_timestamp>, mi::identity<AccountAmendment> >
  >
> AccountAmendmentSet;

typedef AccountAmendmentSet::index<by_timestamp>::type AmendmentsByTimestamp;

class AccountAmendmentHandler {
 public:
  AccountAmendmentHandler(AccountHandler *account_handler,
                          VaultServiceLogic *vault_service_logic)
      : account_handler_(account_handler),
        vault_service_logic_(vault_service_logic),
        amendments_(),
        amendment_mutex_(),
        kKadStoreThreshold_(kad::K * kad::kMinSuccessfulPecentageStore) {}
  ~AccountAmendmentHandler() {}
  // Assumes that response->pmid() has already been set and that
  // request->signed_size() validates
  int ProcessRequest(const maidsafe::AmendAccountRequest *request,
                     maidsafe::AmendAccountResponse *response,
                     google::protobuf::Closure *done);
  // Removes expired amendments from set which have timed out - returns a count
  // of the number of entries removed.
  int CleanUp();
 private:
  AccountAmendmentHandler(const AccountAmendmentHandler&);
  AccountAmendmentHandler& operator=(const AccountAmendmentHandler&);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_CreateNewAmendment);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_AssessAmendment);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_ProcessRequest);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_CleanUp);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesAmendAccount);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesAddToWatchList);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesRemoveFromWatchList);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesAddToReferenceList);
  // Searches and actions the amendment request in an AccountAmendment
  int AssessAmendment(const std::string &owner_pmid,
                      const int &amendment_field,
                      const boost::uint64_t &offer_size,
                      const bool &inc,
                      const PendingAmending &pending,
                      AccountAmendment *amendment);
  void CreateNewAmendment(const AccountAmendment &amendment);
  void CreateNewAmendmentCallback(const AccountAmendment &amendment,
                                  const std::string &find_nodes_response);
  AccountHandler *account_handler_;
  VaultServiceLogic *vault_service_logic_;
  AccountAmendmentSet amendments_;
  boost::mutex amendment_mutex_;
  boost::uint16_t kKadStoreThreshold_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_ACCOUNTAMENDMENTHANDLER_H_
