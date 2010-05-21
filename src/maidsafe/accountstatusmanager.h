/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for caching client or vault's account status.
* Created:      2010-05-18
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

#ifndef MAIDSAFE_ACCOUNTSTATUSMANAGER_H_
#define MAIDSAFE_ACCOUNTSTATUSMANAGER_H_

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>

#include "maidsafe/maidsafe.h"
#include "maidsafe/returncodes.h"
#include "maidsafe/accountholdersmanager.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace maidsafe {

class KadOps;

class AccountStatusManager {
 public:
  AccountStatusManager()
      : space_offered_(0),
        space_given_(0),
        space_taken_(0),
        kMaxUpdateInterval_(600),
        kMaxAmendments_(25),
        mutex_(),
        last_update_(boost::posix_time::neg_infin),
        amendments_since_update_(0) {}
  ~AccountStatusManager() {}
  bool UpdateRequired();
  void SetAccountStatus(const boost::uint64_t &space_offered,
                        const boost::uint64_t &space_given,
                        const boost::uint64_t &space_taken);
  void AccountStatus(boost::uint64_t *space_offered,
                     boost::uint64_t *space_given,
                     boost::uint64_t *space_taken);
  void AdviseAmendment(const AmendAccountRequest::Amendment &amendment_type,
                       const boost::uint64_t &amendment_value);
  bool AbleToStore(const boost::uint64_t &size);
 private:
  AccountStatusManager &operator=(const AccountStatusManager&);
  AccountStatusManager(const AccountStatusManager&);
  FRIEND_TEST(AccountStatusManagerTest, BEH_MAID_ASM_Init);
  FRIEND_TEST(AccountStatusManagerTest, BEH_MAID_ASM_UpdateRequired);
  FRIEND_TEST(AccountStatusManagerTest, BEH_MAID_ASM_AdviseAmendment);
  boost::uint64_t space_offered_;
  boost::uint64_t space_given_;
  boost::uint64_t space_taken_;
  const boost::posix_time::seconds kMaxUpdateInterval_;
  int kMaxAmendments_;
  boost::mutex mutex_;
  boost::posix_time::ptime last_update_;
  int amendments_since_update_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_ACCOUNTSTATUSMANAGER_H_
