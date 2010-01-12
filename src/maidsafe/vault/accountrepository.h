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

#ifndef MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_
#define MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_

#include <boost/multi_index_container.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/maidsafe-dht.h>

#include <list>
#include <map>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace mi = boost::multi_index;

namespace maidsafe_vault {

struct Account {
  std::string pmid_;
  boost::uint64_t offered_;
  boost::uint64_t vault_used_;
  boost::uint64_t account_used_;
  std::list<std::string> alerts_;

  Account(std::string pmid, boost::uint64_t offered, boost::uint64_t vault_used,
          boost::uint64_t account_used, std::list<std::string> alerts)
          : pmid_(pmid), offered_(offered), vault_used_(vault_used),
            account_used_(account_used), alerts_(alerts) {}
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
  AccountHandler() : accounts_(), account_mutex_() {}
  ~AccountHandler() {}
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
 private:
  AccountHandler(const AccountHandler&);
  AccountHandler& operator=(const AccountHandler&);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerInit);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerAddAndFind);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerModify);
  FRIEND_TEST(AccountHandlerTest, BEH_VAULT_AccountHandlerDelete);
  AccountSet accounts_;
  boost::mutex account_mutex_;
};

struct PendingAmending {
  PendingAmending(const maidsafe::AmendAccountRequest *request,
                 maidsafe::AmendAccountResponse *response,
                 google::protobuf::Closure *done)
      : request_(request), response_(response), done_(done) {}
  ~PendingAmending() {}
  const maidsafe::AmendAccountRequest *request_;
  maidsafe::AmendAccountResponse *response_;
  google::protobuf::Closure *done_;
};

struct AccountAmendment {
  AccountAmendment(const std::string &pmid,
                   const int &field,
                   const boost::uint64_t &offer,
                   const bool &increase)
      : pmid_(pmid),
        field_(field),
        offer_(offer),
        increase_(increase),
        chunk_info_holders_(),
        pendings_(),
        expiry_time_(base::get_epoch_time() + kAccountAmendmentTimeout) {}
  bool operator<(const AccountAmendment &aa) const {
    return expiry_time_ < aa.expiry_time_;
  }
  std::string pmid_;
  int field_;
  boost::uint64_t offer_;
  bool increase_;
  std::map<std::string, bool> chunk_info_holders_;
  std::list<PendingAmending> pendings_;
  boost::uint32_t expiry_time_;
};

typedef mi::multi_index_container<
  AccountAmendment,
  mi::indexed_by<
    mi::ordered_non_unique<mi::identity<AccountAmendment> >,
    mi::ordered_non_unique<
      mi::composite_key<
        AccountAmendment,
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, std::string, pmid_),
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, int, field_),
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, boost::uint64_t, offer_),
        BOOST_MULTI_INDEX_MEMBER(AccountAmendment, bool, increase_)
      >
    >
  >
> AccountAmendmentSet;

class AccountAmendmentHandler {
 public:
  explicit AccountAmendmentHandler(AccountHandler *account_handler)
      : account_handler_(account_handler), amendments_(), amendment_mutex_() {}
  ~AccountAmendmentHandler() {}
  // Assume that response->pmid() has already been set and that
  // request->signed_size() validates
  int ProcessRequest(const maidsafe::AmendAccountRequest *request,
                     maidsafe::AmendAccountResponse *response,
                     google::protobuf::Closure *done);
  // Removes entries from set which have timed out
  void CleanUp();
 private:
  AccountAmendmentHandler(const AccountAmendmentHandler&);
  AccountAmendmentHandler& operator=(const AccountAmendmentHandler&);
  AccountHandler *account_handler_;
  AccountAmendmentSet amendments_;
  boost::mutex amendment_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_ACCOUNTREPOSITORY_H_
