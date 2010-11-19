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

#ifndef MAIDSAFE_COMMON_ACCOUNTSTATUSMANAGER_H_
#define MAIDSAFE_COMMON_ACCOUNTSTATUSMANAGER_H_

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/strand.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/function.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

#include <set>
#include <string>

#include "maidsafe/common/maidsafe_service_messages.pb.h"


namespace maidsafe {

namespace test {
class AccountStatusManagerTest_BEH_MAID_ASM_Init_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_AbleToStore_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_SetAndGetAccountStatus_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_ReserveAndUnReserveSpace_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_StartAndStopUpdating_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_DoUpdate_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_AmendmentDone_Test;
class AccountStatusManagerTest_BEH_MAID_ASM_UpdateFailed_Test;
class FuncAccountStatusManagerTest;
}  // namespace test

class KadOps;

class AccountStatusManager {
 public:
  AccountStatusManager();
  ~AccountStatusManager();
  void StartUpdating(boost::function<void()> update_functor);
  void StopUpdating();
  void Update();
  void SetAccountStatus(const boost::uint64_t &space_offered,
                        const boost::uint64_t &space_given,
                        const boost::uint64_t &space_taken);
  void AccountStatus(boost::uint64_t *space_offered,
                     boost::uint64_t *space_given,
                     boost::uint64_t *space_taken);
  void ReserveSpace(const boost::uint64_t &reserved_value);
  void UnReserveSpace(const boost::uint64_t &reserved_value);
  void AmendmentDone(const AmendAccountRequest::Amendment &amendment_type,
                     const boost::uint64_t &amendment_value);
  void UpdateFailed();
  bool AbleToStore(const boost::uint64_t &size);
  friend class test::AccountStatusManagerTest_BEH_MAID_ASM_Init_Test;
  friend class test::AccountStatusManagerTest_BEH_MAID_ASM_AbleToStore_Test;
  friend class
      test::AccountStatusManagerTest_BEH_MAID_ASM_SetAndGetAccountStatus_Test;
  friend class
      test::AccountStatusManagerTest_BEH_MAID_ASM_ReserveAndUnReserveSpace_Test;
  friend class
      test::AccountStatusManagerTest_BEH_MAID_ASM_StartAndStopUpdating_Test;
  friend class test::AccountStatusManagerTest_BEH_MAID_ASM_DoUpdate_Test;
  friend class test::AccountStatusManagerTest_BEH_MAID_ASM_AmendmentDone_Test;
  friend class test::AccountStatusManagerTest_BEH_MAID_ASM_UpdateFailed_Test;
  friend class test::FuncAccountStatusManagerTest;
 private:
  AccountStatusManager &operator=(const AccountStatusManager&);
  AccountStatusManager(const AccountStatusManager&);
  void Run();
  void DoUpdate(const boost::system::error_code &error);
  bool UpdateDone() { return !awaiting_update_result_; }
  boost::uint64_t space_offered_;
  boost::uint64_t space_given_;
  boost::uint64_t space_taken_;
  boost::uint64_t space_reserved_;
  std::multiset<boost::uint64_t> reserved_values_;
  const boost::posix_time::milliseconds kMaxUpdateInterval_;
  const boost::posix_time::milliseconds kFailureRetryInterval_;
  const int kMaxAmendments_;
  boost::mutex mutex_;
  int amendments_since_update_;
  boost::function<void()> update_functor_;
  boost::function<void(const boost::system::error_code &error)> wait_functor_;
  boost::asio::io_service io_service_;
  boost::asio::strand strand_;
  boost::shared_ptr<boost::asio::deadline_timer> timer_;
  boost::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread worker_thread_;
  boost::condition_variable update_done_cond_var_;
  bool awaiting_update_result_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_ACCOUNTSTATUSMANAGER_H_
