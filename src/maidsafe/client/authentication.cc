/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Creates, stores and accesses user details
* Version:      1.0
* Created:      2009-01-28-22.18.47
* Revision:     none
* Author:       Team
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

#include "maidsafe/client/authentication.h"

#include <boost/regex.hpp>

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

void Authentication::Init(boost::shared_ptr<StoreManagerInterface> sm) {
  store_manager_ = sm;
  session_singleton_ = SessionSingleton::getInstance();
  passport_ = session_singleton_->passport_;
  passport_->Init();
}

int Authentication::GetUserInfo(const std::string &username,
                                const std::string &pin) {
  std::string mid_name, smid_name;
  int result =
      passport_->SetInitialDetails(username, pin, &mid_name, &smid_name);

  if (result != kSuccess) {
    tmid_op_status_ = kFailed;
    stmid_op_status_ = kFailed;
    return kAuthenticationError;
  } else {
    tmid_op_status_ = kPendingMid;
    stmid_op_status_ = kPendingMid;
  }

  store_manager_->LoadPacket(mid_name, boost::bind(
      &Authentication::GetMidTmidCallback, this, _1, _2, false));
  store_manager_->LoadPacket(smid_name, boost::bind(
      &Authentication::GetMidTmidCallback, this, _1, _2, true));

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
              boost::bind(&Authentication::TmidOpDone, this));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::GetUserInfo: %s\n", e.what());
#endif
  }
#ifdef DEBUG
  if (!success)
    printf("Authentication::GetUserInfo: timed out waiting for TMID.\n");
#endif
  session_singleton_->SetUsername(username);
  session_singleton_->SetPin(pin);
  {
    boost::mutex::scoped_lock lock(mutex_);
    if (tmid_op_status_ == kSucceeded)
      return kUserExists;
    if (tmid_op_status_ == kNoUser) {
      if (stmid_op_status_ == kNoUser || stmid_op_status_ == kFailed)
        return kUserDoesntExist;
    }
  }
  // Need to wait for STMID result to decide
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
              boost::bind(&Authentication::StmidOpDone, this));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::GetUserInfo: %s\n", e.what());
#endif
  }
#ifdef DEBUG
  if (!success)
    printf("Authentication::GetUserInfo: timed out waiting for STMID.\n");
#endif
  boost::mutex::scoped_lock lock(mutex_);
  if (stmid_op_status_ == kSucceeded)
    return kUserExists;
  if (stmid_op_status_ == kNoUser)
    return kUserDoesntExist;
  else
    return kAuthenticationError;
}

void Authentication::GetMidTmidCallback(const std::vector<std::string> &values,
                                        const ReturnCode &return_code,
                                        bool surrogate) {
  OpStatus op_status;
  {
    boost::mutex::scoped_lock lock(mutex_);
    op_status = (surrogate ? stmid_op_status_ : tmid_op_status_);
    if (return_code != kSuccess || values.empty()) {
      if (surrogate) {
        if (op_status == kPendingMid)
          stmid_op_status_ = kNoUser;
        else
          stmid_op_status_ = kFailed;
      } else {
        if (op_status == kPendingMid)
          tmid_op_status_ = kNoUser;
        else
          tmid_op_status_ = kFailed;
      }
      cond_var_.notify_all();
      return;
    }
  }

#ifdef DEBUG
  if (values.size() != 1)
    printf("Authentication::GetMidTmidCallback - Values: %d\n", values.size());
#endif

  if (op_status == kPendingMid) {
    int result(kSuccess);
    GenericPacket packet;
    if (!packet.ParseFromString(values.at(0)) || packet.data().empty())
      result = kBadPacket;
    std::string tmid_name;
    if (result = kSuccess)
      result = passport_->InitialiseTmid(surrogate, packet.data(), &tmid_name);
    if (result != kSuccess) {
#ifdef DEBUG
      printf("Authentication::GetMidTmidCallback - error %i.\n", result);
#endif
      boost::mutex::scoped_lock lock(mutex_);
      if (surrogate)
        stmid_op_status_ = kFailed;
      else
        tmid_op_status_ = kFailed;
      cond_var_.notify_all();
      return;
    }
    boost::mutex::scoped_lock lock(mutex_);
    if (surrogate)
      stmid_op_status_ = kPendingTmid;
    else
      tmid_op_status_ = kPendingTmid;
    store_manager_->LoadPacket(tmid_name, boost::bind(
        &Authentication::GetMidTmidCallback, this, _1, _2, surrogate));
  } else {
    boost::mutex::scoped_lock lock(mutex_);
    if (surrogate) {
      encrypted_stmid_ = values.at(0);
      stmid_op_status_ = kSucceeded;
      if (tmid_op_status_ == kFailed)
        cond_var_.notify_all();
    } else {
      encrypted_tmid_ = values.at(0);
      tmid_op_status_ = kSucceeded;
      cond_var_.notify_all();
    }
  }
}

int Authentication::GetUserData(const std::string &password,
                                std::string *serialised_data_atlas) {
  //  still have not recovered the tmid
  int result = passport_->GetUserData(password, false, encrypted_tmid_,
                                      serialised_data_atlas);
  DataMap dm;
  if (result != kSuccess || !dm.ParseFromString(*serialised_data_atlas)) {
#ifdef DEBUG
      printf("Authentication::GetUserData - TMID error %i.\n", result);
#endif
    bool success(false);
    try {
      boost::mutex::scoped_lock lock(mutex_);
      tmid_op_status_ = kFailed;
      encrypted_tmid_.clear();
      success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
                boost::bind(&Authentication::StmidOpDone, this));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("Authentication::GetUserData: %s\n", e.what());
#endif
    }
#ifdef DEBUG
    if (!success)
      printf("Authentication::GetUserData: timed out waiting for STMID.\n");
#endif
    if (stmid_op_status_ == kSucceeded) {
      result = passport_->GetUserData(password, true, encrypted_stmid_,
                                      serialised_data_atlas);
      if (result != kSuccess || !dm.ParseFromString(*serialised_data_atlas)) {
#ifdef DEBUG
        printf("Authentication::GetUserData - STMID error %i.\n", result);
#endif
        boost::mutex::scoped_lock lock(mutex_);
        stmid_op_status_ = kFailed;
        encrypted_stmid_.clear();
      } else {
        session_singleton_->SetPassword(password);
#ifdef DEBUG
        printf("Authentication::GetUserData - Using STMID\n");
#endif
        return kSuccess;
      }
    }
    return kPasswordFailure;
  }
#ifdef DEBUG
  printf("Authentication::GetUserData - Using TMID\n");
#endif
  session_singleton_->SetPassword(password);
  return kSuccess;
}

int Authentication::CreateUserSysPackets(const std::string &username,
                                         const std::string &pin) {
  bool already_initialised(false);
  {
    boost::mutex::scoped_lock lock(mutex_);
    if (tmid_op_status_ == kNoUser) {
      if (stmid_op_status_ == kNoUser || stmid_op_status_ == kFailed)
        already_initialised = true;
    } else if (tmid_op_status_ == kFailed) {
      if (stmid_op_status_ == kNoUser || stmid_op_status_ == kFailed)
        already_initialised = true;
    }
  }

  if (!already_initialised) {
#ifdef DEBUG
    printf("Authentication::CreateUserSysPackets - NOT INTIALISED\n");
#endif
//    passport_->Clear();
//    std::string mid_name, smid_name;
//    int result =
//        passport_->SetInitialDetails(username, pin, &mid_name, &smid_name);
//
//    if (result != kSuccess) {
//      tmid_op_status_ = kFailed;
//      stmid_result_ = kFailed;
//      return kAuthenticationError;
//    } else {
//      tmid_op_status_ = kPendingMid;
//      stmid_result_ = kPendingMid;
//    }
    return kAuthenticationError;
  }
  session_singleton_->SetUsername(username);
  session_singleton_->SetPin(pin);

  OpStatus anmaid_status(kPending);
  CreateSignaturePacket(passport::ANMAID, 0, &anmaid_status, NULL);

  OpStatus anmid_status(kPending);
  CreateSignaturePacket(passport::ANMID, 0, &anmid_status, NULL);

  OpStatus antmid_status(kPending);
  CreateSignaturePacket(passport::ANTMID, 0, &antmid_status, NULL);

// TODO(Fraser#5#): 2010-10-18 - Thread these next two?
  OpStatus maid_status(kPending);
  CreateSignaturePacket(passport::MAID, 0, &maid_status, &anmaid_status);

  OpStatus pmid_status(kPending);
  CreateSignaturePacket(passport::PMID, 0, &pmid_status, &maid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(15 * kSingleOpTimeout_),
              boost::bind(&Authentication::SystemPacketsOpDone, this,
                          pmid_status, anmid_status, antmid_status));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::CreateUserSysPackets: %s\n", e.what());
#endif
    success = false;
  }
#ifdef DEBUG
  if (!success) {
    printf("Authentication::CreateUserSysPackets: timed out.\n");
  }
#endif
  if ((anmaid_status == kSucceeded) && (anmid_status == kSucceeded) &&
      (antmid_status == kSucceeded) && (maid_status == kSucceeded) &&
      (pmid_status == kSucceeded)) {
    return kSuccess;
  } else {
    return kAuthenticationError;
  }
}

void Authentication::CreateSignaturePacket(
    const passport::PacketType &packet_type,
    boost::uint8_t attempt,
    OpStatus *op_status,
    OpStatus *dependent_op_status) {
  // Wait for dependent op or timeout.
  bool success(true);
  if (dependent_op_status) {
    boost::mutex::scoped_lock lock(mutex_);
    try {
      success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(3 * kSingleOpTimeout_),
                boost::bind(&Authentication::SignerDone, this,
                            dependent_op_status));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("Authentication::CreateSigPkt (%i): %s\n", packet_type, e.what());
#endif
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::CreateSigPkt (%i): failed wait.\n", packet_type);
#endif
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Create packet
  boost::shared_ptr<passport::SignaturePacket> sig_packet;
  int result(kPendingResult);
  if (packet_type == passport::MPID) {
    if (attempt == 0)
      result = passport_->InitialiseMpid(public_name_, sig_packet);
  } else {
    result = passport_->InitialiseSignaturePacket(packet_type, sig_packet);
  }
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::CreateSigPkt (%i): failed init.\n", packet_type);
#endif
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Check packet name is not already a key on the DHT
  VoidFuncOneInt func = boost::bind(&Authentication::PacketUniqueCallback, this,
                                    _1, sig_packet, attempt, op_status);
  store_manager_->KeyUnique(sig_packet->name(), false, func);
}

void Authentication::PacketUniqueCallback(const ReturnCode &return_code,
                                          boost::shared_ptr<pki::Packet> packet,
                                          boost::uint8_t attempt,
                                          OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  if (return_code != kKeyUnique) {
    if ((attempt == kMaxStoreAttempts_ - 1) ||
        (packet_type == passport::MPID)) {
      boost::mutex::scoped_lock lock(mutex_);
#ifdef DEBUG
      printf("Authentication::PacketUniqueCallback (%i): Failed to store. No "
             "more retries.\n", packet_type);
#endif
      *op_status = kFailed;
      cond_var_.notify_all();
      return;
    } else {
#ifdef DEBUG
      printf("Authentication::PacketUniqueCallback (%i): Failed to store. "
             "Retry %i.\n", packet_type, attempt + 1);
#endif
      CreateSignaturePacket(packet_type, attempt + 1, op_status, NULL);
      return;
    }
  }

  // Store packet
  VoidFuncOneInt functor = boost::bind(
      &Authentication::StoreOrDeletePacketCallback, this, _1,
      packet->packet_type(), true, attempt, op_status);
  if (packet->packet_type() == passport::MSID) {
    store_manager_->StorePacket(packet->name(), packet->value(),
                                packet->packet_type(), PRIVATE, "", functor);
  } else {
    store_manager_->StorePacket(packet->name(), packet->value(),
                                packet->packet_type(), PRIVATE, "", functor);
  }
}

void Authentication::StoreOrDeletePacketCallback(
    const ReturnCode &return_code,
    const passport::PacketType &packet_type,
    bool storing,
    boost::uint8_t attempt,
    OpStatus *op_status) {
  bool is_last_attempt = (storing && (attempt == kMaxStoreAttempts_ - 1)) ||
                         (!storing && (attempt == kMaxDeleteAttempts_ - 1));
  {
    boost::mutex::scoped_lock lock(mutex_);
    if (return_code == kSuccess) {
      *op_status = kSucceeded;
      cond_var_.notify_all();
      return;
    } else if (is_last_attempt) {
#ifdef DEBUG
      std::string dbg(storing ? "store" : "delete");
      printf("Authentication::StoreOrDeletePktCb (%i): Failed to %s. No "
             "more retries.\n", packet_type, dbg.c_str());
#endif
      *op_status = kFailed;
      cond_var_.notify_all();
      return;
    }
  }
#ifdef DEBUG
  std::string dbg(storing ? "store" : "delete");
  printf("Authentication::StoreOrDeletePktCb (%i): Failed to %s. Retry %i"
         ".\n", packet_type, dbg.c_str(), attempt + 1);
#endif
  if (storing)
    CreateSignaturePacket(packet_type, attempt + 1, op_status, NULL);
  else
    DeletePacket(packet_type, attempt + 1, op_status, NULL);
}

int Authentication::CreateTmidPacket(const std::string &username,
                                     const std::string &pin,
                                     const std::string &password,
                                     const std::string &serialised_datamap) {
  if ((username != session_singleton_->Username()) ||
      (pin != session_singleton_->Pin())) {
#ifdef DEBUG
    printf("Authentication::CreateTmidPacket: username/pin error.\n");
#endif
    return kAuthenticationError;
  }

  boost::shared_ptr<passport::MidPacket> mid;
  boost::shared_ptr<passport::TmidPacket> tmid;
  int result(kPendingResult);
  boost::uint8_t attempt(0);
  while ((result != kSuccess) && (attempt < kMaxStoreAttempts_)) {
    result = passport_->SetNewUserData(password, serialised_datamap, mid, tmid);
    if (result != kSuccess) {
#ifdef DEBUG
      printf("Authentication::CreateTmidPacket: failed init.\n");
#endif
      return kAuthenticationError;
    }
    bool unique((PacketUnique(mid) == kKeyUnique) &&
                (PacketUnique(tmid) == kKeyUnique));
    if (!unique) {
#ifdef DEBUG
      printf("Authentication::CreateTmidPacket: MID or TMID already exists.\n");
#endif
      ++attempt;
      result = kKeyNotUnique;
      continue;
    }
    result = StorePacket(mid, false);
    if (result == kSuccess)
      result = StorePacket(tmid, false);
    ++attempt;
  }

  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::CreateTmidPacket: failed.\n");
#endif
    return kAuthenticationError;
  } else {
    return kSuccess;
  }
}

int Authentication::CreateMsidPacket(std::string *msid_name,
                                     std::string *msid_public_key,
                                     std::string *msid_private_key) {
  if (!msid_name || !msid_public_key || !msid_private_key)
    return kAuthenticationError;
  msid_name->clear();
  msid_public_key->clear();
  msid_private_key->clear();

  boost::shared_ptr<passport::SignaturePacket> msid;
  int result(kPendingResult);
  boost::uint8_t attempt(0);
  std::vector<boost::uint32_t> share_stats(2, 0);
  while ((result != kSuccess) && (attempt < kMaxStoreAttempts_)) {
    result = passport_->InitialiseSignaturePacket(passport::MSID, msid);
    if (result != kSuccess) {
#ifdef DEBUG
      printf("Authentication::CreateMsidPacket: failed init.\n");
#endif
      return kAuthenticationError;
    }
    // Add the share to the session to allow store_manager to retrieve the keys.
    std::vector<std::string> attributes;
    attributes.push_back(msid->name());
    attributes.push_back(msid->name());
    attributes.push_back(msid->value());  // msid->value == msid->public_key
    attributes.push_back(msid->private_key());
    result = session_singleton_->AddPrivateShare(attributes, share_stats, NULL);
    if (result != kSuccess) {
#ifdef DEBUG
      printf("Authentication::CreateMsidPacket: failed adding to session.\n");
#endif
      session_singleton_->DeletePrivateShare(msid->name(), 0);
      return kAuthenticationError;
    }
    result = StorePacket(msid, true);
#ifdef DEBUG
    if (result != kSuccess)
      printf("Authentication::CreateMsidPacket: failed storing MSID.\n");
#endif
    // Remove the share from the session again to allow CC to add it fully.
    session_singleton_->DeletePrivateShare(msid->name(), 0);
    ++attempt;
  }

  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::CreateMsidPacket: failed.\n");
#endif
    return kAuthenticationError;
  } else {
    *msid_name = msid->name();
    *msid_public_key = msid->value();
    *msid_private_key = msid->private_key();
    return kSuccess;
  }
}

void Authentication::SaveSession(const std::string &serialised_data_atlas,
                                 const VoidFuncOneInt &functor) {
  boost::shared_ptr<SaveSessionData>
      save_session_data(new SaveSessionData(functor, kRegular));

  std::string mid_old_value, smid_old_value;
  boost::shared_ptr<passport::MidPacket> updated_mid, updated_smid;
  boost::shared_ptr<passport::TmidPacket> new_tmid, tmid_for_deletion;
  int result = passport_->UpdateUserData(serialised_data_atlas, &mid_old_value,
      &smid_old_value, updated_mid, updated_smid, new_tmid, tmid_for_deletion);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::SaveSession: failed UpdateUserData.\n");
#endif
    functor(kAuthenticationError);
    return;
  }
                                    // TODO(Fraser#5#): 2010-10-18 - Have method for retrying for MID and SMID
                                    //                               failures independently.

  // Update or store SMID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                        this, _1, updated_smid,
                                        save_session_data);
  if (smid_old_value.empty()) {
    store_manager_->StorePacket(updated_smid->name(), updated_smid->value(),
                                passport::SMID, PRIVATE, "", callback);
  } else {
    store_manager_->UpdatePacket(updated_smid->name(), smid_old_value,
                                 updated_smid->value(), passport::SMID, PRIVATE,
                                 "", callback);
  }

  // Update MID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         updated_mid, save_session_data);
  store_manager_->UpdatePacket(updated_mid->name(), mid_old_value,
                               updated_mid->value(), passport::MID, PRIVATE, "",
                               callback);

  // Store new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_tmid, save_session_data);
  store_manager_->StorePacket(new_tmid->name(), new_tmid->value(),
                              passport::TMID, PRIVATE, "", callback);

  // Delete old STMID
  if (tmid_for_deletion.get()) {
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           tmid_for_deletion, save_session_data);
    std::vector<std::string> values(1, tmid_for_deletion->value());
    store_manager_->DeletePacket(tmid_for_deletion->name(), values,
                                 passport::TMID, PRIVATE, "", callback);
  } else {
    boost::mutex::scoped_lock lock(mutex_);
    save_session_data->process_stmid = kSucceeded;
  }
}

void Authentication::SaveSessionCallback(
    const ReturnCode &return_code,
    boost::shared_ptr<pki::Packet> packet,
    boost::shared_ptr<SaveSessionData> save_session_data) {
  OpStatus op_status(kSucceeded);
  if ((save_session_data->op_type == kUnique && return_code != kKeyUnique) ||
      (save_session_data->op_type != kUnique && return_code != kSuccess)) {
#ifdef DEBUG
    printf("Authentication::SaveSessionCallback (%i): Return Code %i\n",
           packet->packet_type(), return_code);
#endif
    op_status = kFailed;
  }
  boost::mutex::scoped_lock lock(mutex_);
  switch (packet->packet_type()) {
    case passport::MID:
      save_session_data->process_mid = op_status;
      break;
    case passport::SMID:
      save_session_data->process_smid = op_status;
      break;
    case passport::TMID:
      save_session_data->process_tmid = op_status;
      break;
    case passport::STMID:
      save_session_data->process_stmid = op_status;
      break;
    default:
      break;
  }
  if ((save_session_data->process_mid == kPending) ||
      (save_session_data->process_smid == kPending) ||
      (save_session_data->process_tmid == kPending) ||
      (save_session_data->process_stmid == kPending))
    return;
  if ((save_session_data->process_mid == kFailed) ||
      (save_session_data->process_smid == kFailed) ||
      (save_session_data->process_tmid == kFailed)) {
    lock.unlock();
    save_session_data->functor(kAuthenticationError);
    return;
  }
  if ((save_session_data->process_stmid == kFailed)) {
    lock.unlock();
    if (save_session_data->op_type == kRegular)
      save_session_data->functor(kFailedToDeleteOldPacket);
    else
      save_session_data->functor(kAuthenticationError);
    return;
  }
  lock.unlock();
  save_session_data->functor(kSuccess);
}

int Authentication::SaveSession(const std::string &serialised_data_atlas) {
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  SaveSession(serialised_data_atlas, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(12 * kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::SaveSession: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::SaveSession: timed out.\n");
#endif
    return kAuthenticationError;
  }
  return result;
}

int Authentication::CreatePublicName(const std::string &public_name) {
  public_name_ = public_name;
  OpStatus anmpid_status(kPending);
  CreateSignaturePacket(passport::ANMPID, 0, &anmpid_status, NULL);

// TODO(Fraser#5#): 2010-10-18 - Thread this?
  OpStatus mpid_status(kPending);
  CreateSignaturePacket(passport::MPID, 0, &mpid_status, &anmpid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(6 * kSingleOpTimeout_),
              boost::bind(&Authentication::SystemPacketsOpDone, this,
                          mpid_status, anmpid_status));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::CreatePublicName: %s\n", e.what());
#endif
    success = false;
  }
#ifdef DEBUG
  if (!success) {
    printf("Authentication::CreatePublicName: timed out.\n");
  }
#endif
  if ((anmpid_status == kSucceeded) && (mpid_status == kSucceeded)) {
    return kSuccess;
  } else {
    return kAuthenticationError;
  }
}

int Authentication::RemoveMe() {
// TODO(Fraser#5#): 2010-10-18 - Thread these?
  OpStatus pmid_status(kPending);
  DeletePacket(passport::PMID, 0, &pmid_status, NULL);
  OpStatus maid_status(kPending);
  DeletePacket(passport::MAID, 0, &maid_status, &pmid_status);
  OpStatus anmaid_status(kPending);
  DeletePacket(passport::ANMAID, 0, &anmaid_status, &maid_status);

  OpStatus tmid_status(kPending);
  DeletePacket(passport::TMID, 0, &tmid_status, NULL);
  OpStatus stmid_status(kPending);
  DeletePacket(passport::STMID, 0, &stmid_status, &tmid_status);
  OpStatus antmid_status(kPending);
  DeletePacket(passport::ANTMID, 0, &antmid_status, &stmid_status);

  OpStatus mid_status(kPending);
  DeletePacket(passport::MID, 0, &mid_status, NULL);
  OpStatus anmid_status(kPending);
  DeletePacket(passport::ANMID, 0, &anmid_status, &mid_status);

  OpStatus smid_status(kPending);
  DeletePacket(passport::SMID, 0, &smid_status, NULL);
  OpStatus ansmid_status(kPending);
  DeletePacket(passport::ANSMID, 0, &ansmid_status, &smid_status);

  OpStatus mpid_status(kPending);
  DeletePacket(passport::MPID, 0, &mpid_status, NULL);
  OpStatus anmpid_status(kPending);
  DeletePacket(passport::ANMPID, 0, &anmpid_status, &mpid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(12 * kSingleOpTimeout_),
              boost::bind(&Authentication::SystemPacketsOpDone, this,
                          anmaid_status, antmid_status, anmid_status,
                          ansmid_status, anmpid_status));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::RemoveMe: %s\n", e.what());
#endif
    success = false;
  }
#ifdef DEBUG
  if (!success) {
    printf("Authentication::RemoveMe: timed out.\n");
  }
#endif
  // Really only need these to be deleted
  if ((pmid_status == kSucceeded) && (maid_status == kSucceeded) &&
      (tmid_status == kSucceeded) && (stmid_status == kSucceeded) &&
      (mpid_status == kSucceeded)) {
    return kSuccess;
  } else {
    return kAuthenticationError;
  }
}

void Authentication::DeletePacket(const passport::PacketType &packet_type,
                                  boost::uint8_t attempt,
                                  OpStatus *op_status,
                                  OpStatus *dependent_op_status) {
  // Wait for dependent op or timeout.
  bool success(true);
  if (dependent_op_status) {
    boost::mutex::scoped_lock lock(mutex_);
    try {
      success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(kSingleOpTimeout_),
                boost::bind(&Authentication::SignerDone, this,
                            dependent_op_status));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("Authentication::DeletePacket (%i): %s\n", packet_type, e.what());
#endif
      success = false;
    }
    success = (*dependent_op_status == kSucceeded);
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::DeletePacket (%i): failed wait.\n", packet_type);
#endif
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kFailed;
    cond_var_.notify_all();
    return;
  }

  // Retrieve packet
  boost::shared_ptr<pki::Packet> packet(passport_->Packet(packet_type));
  if (!packet.get()) {
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kSucceeded;
    cond_var_.notify_all();
    return;
  }

  // Delete packet
  VoidFuncOneInt functor = boost::bind(
      &Authentication::StoreOrDeletePacketCallback, this, _1, packet_type,
      false, attempt, op_status);
  std::vector<std::string> values(1, packet->value());
  store_manager_->DeletePacket(packet->name(), values, packet_type, PRIVATE, "",
                               functor);
}

int Authentication::ChangeUsername(const std::string &serialised_data_atlas,
                                   const std::string &new_username) {
  return ChangeUserData(serialised_data_atlas, new_username,
                        session_singleton_->Pin());
}

int Authentication::ChangePin(const std::string &serialised_data_atlas,
                              const std::string &new_pin) {
  return ChangeUserData(serialised_data_atlas, session_singleton_->Username(),
                        new_pin);
}

int Authentication::ChangeUserData(const std::string &serialised_data_atlas,
                                   const std::string &new_username,
                                   const std::string &new_pin) {
  // Get updated packets
  boost::shared_ptr<passport::MidPacket> mid_for_deletion, smid_for_deletion;
  boost::shared_ptr<passport::TmidPacket> tmid_for_deletion, stmid_for_deletion;
  boost::shared_ptr<passport::MidPacket> new_mid, new_smid;
  boost::shared_ptr<passport::TmidPacket> new_tmid, new_stmid;
  int result = passport_->ChangeUserData(new_username, new_pin,
               serialised_data_atlas, mid_for_deletion, smid_for_deletion,
               tmid_for_deletion, stmid_for_deletion, new_mid, new_smid,
               new_tmid, new_stmid);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: failed ChangeUserData.\n");
#endif
    return kAuthenticationError;
  }

  int uniqueness_result(kPendingResult);
  VoidFuncOneInt uniqueness_functor = boost::bind(
      &Authentication::PacketOpCallback, this, _1, &uniqueness_result);
  boost::shared_ptr<SaveSessionData>
      check_uniqueness(new SaveSessionData(uniqueness_functor, kUnique));

  // Check new MID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                        this, _1, new_mid, check_uniqueness);
  store_manager_->KeyUnique(new_mid->name(), false, callback);
  // Check new SMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_smid, check_uniqueness);
  store_manager_->KeyUnique(new_smid->name(), false, callback);
  // Check new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_tmid, check_uniqueness);
  store_manager_->KeyUnique(new_tmid->name(), false, callback);
  // Check new STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_stmid, check_uniqueness);
  store_manager_->KeyUnique(new_stmid->name(), false, callback);

  // Wait for checking to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(12 * kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this,
                          &uniqueness_result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: checking: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: timed out storing.\n");
#endif
    return kAuthenticationError;
  }
  if (uniqueness_result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: non-unique packets.\n");
#endif
    return kUserExists;
  }

  int store_result(kPendingResult);
  boost::uint8_t attempt(0);
  VoidFuncOneInt store_functor = boost::bind(&Authentication::PacketOpCallback,
                                             this, _1, &store_result);
  while ((store_result != kSuccess) && (attempt < kMaxStoreAttempts_)) {
    boost::shared_ptr<SaveSessionData>
        save_new_packets(new SaveSessionData(store_functor, kSaveNew));

    // Store new MID
    VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                          this, _1, new_mid, save_new_packets);
    store_manager_->StorePacket(new_mid->name(), new_mid->value(),
                                passport::MID, PRIVATE, "", callback);
    // Store new SMID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           new_smid, save_new_packets);
    store_manager_->StorePacket(new_smid->name(), new_smid->value(),
                                passport::SMID, PRIVATE, "", callback);
    // Store new TMID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           new_tmid, save_new_packets);
    store_manager_->StorePacket(new_tmid->name(), new_tmid->value(),
                                passport::TMID, PRIVATE, "", callback);
    // Store new STMID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           new_stmid, save_new_packets);
    store_manager_->StorePacket(new_stmid->name(), new_stmid->value(),
                                passport::TMID, PRIVATE, "", callback);

    // Wait for storing to complete
    bool success(true);
    try {
      boost::mutex::scoped_lock lock(mutex_);
      success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(12 * kSingleOpTimeout_),
                boost::bind(&Authentication::PacketOpDone, this,
                            &store_result));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("Authentication::ChangeUserData: storing: %s\n", e.what());
#endif
      success = false;
    }
    if (!success) {
#ifdef DEBUG
      printf("Authentication::ChangeUserData: timed out storing attempt %u\n",
             attempt);
#endif
      store_result = kPendingResult;
    }
    if (store_result != kSuccess) {
#ifdef DEBUG
      printf("Authentication::ChangeUserData: storing packets failed, "
             "attempt %u\n", attempt);
#endif
    }
    ++attempt;
  }
  if (store_result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: storing packets failed overall.\n");
#endif
    // TODO(Fraser#5#): 2010-10-18 - Revert passport
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  int delete_result(kPendingResult);
  attempt = 0;
  VoidFuncOneInt delete_functor = boost::bind(&Authentication::PacketOpCallback,
                                             this, _1, &delete_result);
  while ((delete_result != kSuccess) && (attempt < kMaxDeleteAttempts_)) {
    boost::shared_ptr<SaveSessionData>
        delete_old_packets(new SaveSessionData(delete_functor, kDeleteOld));

    // Delete old MID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           mid_for_deletion, delete_old_packets);
    std::vector<std::string> values(1, mid_for_deletion->value());
    store_manager_->DeletePacket(mid_for_deletion->name(), values,
                                 passport::MID, PRIVATE, "", callback);
    // Delete old SMID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           smid_for_deletion, delete_old_packets);
    values.assign(1, smid_for_deletion->value());
    store_manager_->DeletePacket(smid_for_deletion->name(), values,
                                 passport::SMID, PRIVATE, "", callback);
    // Delete old TMID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           tmid_for_deletion, delete_old_packets);
    values.assign(1, tmid_for_deletion->value());
    store_manager_->DeletePacket(tmid_for_deletion->name(), values,
                                 passport::TMID, PRIVATE, "", callback);
    // Delete old STMID
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           stmid_for_deletion, delete_old_packets);
    values.assign(1, stmid_for_deletion->value());
    store_manager_->DeletePacket(stmid_for_deletion->name(), values,
                                 passport::TMID, PRIVATE, "", callback);

    try {
      boost::mutex::scoped_lock lock(mutex_);
      success = cond_var_.timed_wait(lock,
                boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
                boost::bind(&Authentication::PacketOpDone, this,
                            &delete_result));
    }
    catch(const std::exception &e) {
  #ifdef DEBUG
      printf("Authentication::ChangeUserData: deleting: %s\n", e.what());
  #endif
      success = false;
    }
  #ifdef DEBUG
    if (!success)
      printf("Authentication::ChangeUserData: timed out deleting.\n");
  #endif
    ++attempt;
  }
  // Result of deletions not considered here.
  return kSuccess;
}

int Authentication::ChangePassword(const std::string &serialised_data_atlas,
                                   const std::string &new_password) {
  // Get updated packets
  std::string tmid_old_value, stmid_old_value;
  boost::shared_ptr<passport::TmidPacket> updated_tmid, updated_stmid;
  int result = passport_->ChangePassword(new_password, serialised_data_atlas,
                                         &tmid_old_value, &stmid_old_value,
                                         updated_tmid, updated_stmid);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangePassword: failed ChangePassword.\n");
#endif
    return kAuthenticationError;
  }

  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  boost::shared_ptr<SaveSessionData>
      update_packets(new SaveSessionData(functor, kUpdate));
  update_packets->process_mid = kSucceeded;
  update_packets->process_smid = kSucceeded;

  // Update TMID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                        this, _1, updated_tmid, update_packets);
  store_manager_->UpdatePacket(updated_tmid->name(), tmid_old_value,
                               updated_tmid->value(), passport::TMID,
                               PRIVATE, "", callback);
  // Update STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         updated_stmid, update_packets);
  store_manager_->UpdatePacket(updated_stmid->name(), stmid_old_value,
                               updated_stmid->value(), passport::TMID,
                               PRIVATE, "", callback);

  // Wait for update to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::ChangePassword: updating: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::ChangePassword: timed out updating.\n");
#endif
    return kAuthenticationError;
  }
  return result;
}

bool Authentication::CheckUsername(const std::string &username) {
  try {
    return UtilsTrim(username).size() >= 4;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::CheckUsername: %s\n", e.what());
#endif
    return false;
  }
}

bool Authentication::CheckPin(std::string pin) {
  try {
    pin = UtilsTrim(pin);
    if (pin == "0000")
      return false;
    boost::regex reg_ex("\\d{4}");
    return boost::regex_match(pin, reg_ex);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::CheckPin: %s\n", e.what());
#endif
    return false;
  }
}

bool Authentication::CheckPassword(const std::string &password) {
  try {
    return UtilsTrim(password).size() >= 4;
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::CheckPassword: %s\n", e.what());
#endif
    return false;
  }
}

int Authentication::StorePacket(boost::shared_ptr<pki::Packet> packet,
                                bool check_uniqueness) {
  int result(kPendingResult);
  if (check_uniqueness) {
    result = PacketUnique(packet);
    if (result != kKeyUnique) {
#ifdef DEBUG
      printf("Authentication::StorePacket: key already exists.\n");
#endif
      return result;
    }
  }
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }
  store_manager_->StorePacket(packet->name(), packet->value(),
                              packet->packet_type(), dir_type, msid, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::StorePacket: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::StorePacket: timed out.\n");
#endif
    return kAuthenticationError;
  }
#ifdef DEBUG
  if (result != kSuccess)
    printf("!!!!!!!!!!!!!!!!!!!!!\nAuthentication::StorePacket %i\n\n", result);
#endif
  return result;
}

int Authentication::DeletePacket(boost::shared_ptr<pki::Packet> packet) {
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  std::vector<std::string> values(1, packet->value());
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }
  store_manager_->DeletePacket(packet->name(), values, packet->packet_type(),
                               dir_type, msid, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::DeletePacket: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::DeletePacket: timed out.\n");
#endif
    return kAuthenticationError;
  }
#ifdef DEBUG
  if (result != kSuccess)
    printf("!!!!!!!!!!!!!!!!!!!!\nAuthentication::DeletePacket %i\n\n", result);
#endif
  return result;
}

int Authentication::PacketUnique(boost::shared_ptr<pki::Packet> packet) {
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }
  store_manager_->KeyUnique(packet->name(), false, functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this, &result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::PacketUnique: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::PacketUnique: timed out.\n");
#endif
    return kAuthenticationError;
  }
  return result;
}

void Authentication::PacketOpCallback(const ReturnCode &return_code,
                                      int *op_result) {
  boost::mutex::scoped_lock lock(mutex_);
  *op_result = return_code;
  cond_var_.notify_all();
}

char *Authentication::UtilsTrimRight(char *szSource) {
  char *pszEOS = NULL;
  //  Set pointer to character before terminating NULL
  pszEOS = szSource + strlen(szSource) - 1;
  //  iterate backwards until non '_' is found
  while ((pszEOS >= szSource) && (*pszEOS == ' '))
    --*pszEOS = '\0';
  return szSource;
}

char *Authentication::UtilsTrimLeft(char *szSource) {
  char *pszBOS = NULL;
  //  Set pointer to first character
  pszBOS = szSource;
  //  iterate forwards until non '_' is found
  while (*pszBOS == ' ')
    ++*pszBOS;
  return pszBOS;
}

std::string Authentication::UtilsTrim(std::string source) {
  return UtilsTrimLeft(UtilsTrimRight(UtilsTrimLeft(&source.at(0))));
}


}  // namespace maidsafe
