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

#include "maidsafe/accountstatusmanager.h"

namespace maidsafe {

bool AccountStatusManager::UpdateRequired() {
  boost::mutex::scoped_lock lock(mutex_);
  return (boost::posix_time::microsec_clock::universal_time() >=
          last_update_ + kMaxUpdateInterval_) ||
         (amendments_since_update_ > kMaxAmendments_);
}

void AccountStatusManager::SetAccountStatus(
    const boost::uint64_t &space_offered,
    const boost::uint64_t &space_given,
    const boost::uint64_t &space_taken) {
  boost::mutex::scoped_lock lock(mutex_);
  space_offered_ = space_offered;
  space_given_ = space_given;
  space_taken_ = space_taken;
  last_update_ = boost::posix_time::microsec_clock::universal_time();
  amendments_since_update_ = 0;
}

void AccountStatusManager::AccountStatus(boost::uint64_t *space_offered,
                                         boost::uint64_t *space_given,
                                         boost::uint64_t *space_taken) {
  boost::mutex::scoped_lock lock(mutex_);
  *space_offered = space_offered_;
  *space_given = space_given_;
  *space_taken = space_taken_;
}
  
void AccountStatusManager::AdviseAmendment(
    const AmendAccountRequest::Amendment &amendment_type,
    const boost::uint64_t &amendment_value) {
  boost::mutex::scoped_lock lock(mutex_);
  switch (amendment_type) {
    case AmendAccountRequest::kSpaceOffered:
      space_offered_ = amendment_value;
      break;
    case AmendAccountRequest::kSpaceGivenInc:
      space_given_ += amendment_value;
      break;
    case AmendAccountRequest::kSpaceGivenDec:
      if (amendment_value >= space_given_)
        space_given_ = 0;
      else
        space_given_ -= amendment_value;
      break;
    case AmendAccountRequest::kSpaceTakenInc:
      space_taken_ += amendment_value;
      break;
    case AmendAccountRequest::kSpaceTakenDec:
      if (amendment_value >= space_taken_)
        space_taken_ = 0;
      else
        space_taken_ -= amendment_value;
      break;
  }
  ++amendments_since_update_;
}

bool AccountStatusManager::AbleToStore(const boost::uint64_t &size) {
  boost::mutex::scoped_lock lock(mutex_);
  return space_taken_ + size <= space_offered_;
}

}  // namespace maidsafe
