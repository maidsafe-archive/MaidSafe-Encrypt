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

//#include <boost/array.hpp>
//#include <boost/lexical_cast.hpp>
//#include <boost/regex.hpp>
//#include <boost/thread/mutex.hpp>
//
//#include <vector>

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"

//#include "maidsafe/passport/systempackets.h"
//#include "maidsafe/maidsafe.h"
//#include "protobuf/datamaps.pb.h"
//#include "protobuf/maidsafe_messages.pb.h"
//#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe {

void Authentication::Init(const boost::uint16_t &crypto_key_buffer_count,
                          boost::shared_ptr<StoreManagerInterface> storemanager,
                          boost::shared_ptr<passport::Passport> passport) {
  store_manager_ = storemanager;
  session_singleton_ = SessionSingleton::getInstance();
  crypto_.set_hash_algorithm(crypto::SHA_512);
  crypto_.set_symm_algorithm(crypto::AES_256);
  passport_ = passport;
  passport_->Init(crypto_key_buffer_count);
}

int Authentication::GetUserInfo(const std::string &username,
                                const std::string &pin) {
  std::string mid_name, smid_name;
  int result =
      passport_->SetInitialDetails(username, pin, &mid_name, &smid_name);

  if (result != kSuccess) {
    tmid_op_status_ = kFailed;
    stmid_result_ = kFailed;
    return kAuthenticationError;
  } else {
    tmid_op_status_ = kPendingMid;
    stmid_result_ = kPendingMid;
  }

  store_manager_->LoadPacket(mid_name, boost::bind(
      &Authentication::GetMidSmidCallback, this, _1, _2, false));
  store_manager_->LoadPacket(smid_name, boost::bind(
      &Authentication::GetMidSmidCallback, this, _1, _2, true));

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock, boost::posix_time::milliseconds(60000),
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
    success = cond_var_.timed_wait(lock, boost::posix_time::milliseconds(60000),
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
    printf("Authentication::GetMidCallback - Values: %d\n", values.size());
#endif

  if (op_status == kPendingMid) {
    std::string tmid_name;
    int result = passport->InitialiseTmid(surrogate, values.at(0), &tmid_name);
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
    store_manager_->LoadPacket(tmid_name,
        boost::bind(&Authentication::GetTmidStmidCallback, this, _1, _2,
                    surrogate, user_info));
  } else {
    boost::mutex::scoped_lock lock(mutex_);
    if (surrogate) {
      serialised_stmid_packet_ = values.at(0);
      user_info->stmid_callback_status = UserInfo::kSucceeded;
      if (user_info->tmid_callback_status == UserInfo::kFailed) {
        user_info_result_ = kUserExists;
        cond_var_.notify_all();
      }
    } else {
      serialised_tmid_packet_ = values.at(0);
      user_info->tmid_callback_status = UserInfo::kSucceeded;
      user_info_result_ = kUserExists;
      cond_var_.notify_all();
    }
  }
}


int Authentication::GetUserData(const std::string &password,
                                std::string *serialised_data_atlas) {
  //  still have not recovered the tmid
  int result = passport->GetUserData(password, false, serialised_tmid_packet_,
                                     serialised_data_atlas);
  DataMap dm;
  if (result != kSuccess || !dm.ParseFromString(*serialised_data_atlas)) {
#ifdef DEBUG
      printf("Authentication::GetUserData - TMID error %i.\n", result);
#endif
    try {
      boost::mutex::scoped_lock lock(mutex_);
      tmid_op_status_ = kFailed;
      serialised_tmid_packet_.clear();
      success = cond_var_.timed_wait(lock,
          boost::posix_time::milliseconds(60000),
          boost::bind(&Authentication::SerialisedStmidPacketSet, this));
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
    if (stmid_op_status_ == kSucceeded) {
      result = passport->GetUserData(password, true, serialised_stmid_packet_,
                                     serialised_data_atlas);
      if (result != kSuccess || !dm.ParseFromString(*serialised_data_atlas)) {
#ifdef DEBUG
        printf("Authentication::GetUserData - STMID error %i.\n", result);
#endif
        boost::mutex::scoped_lock lock(mutex_);
        stmid_op_status_ = kFailed;
        serialised_stmid_packet_.clear();
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
    success = cond_var_.timed_wait(lock,boost::posix_time::milliseconds(60000),
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
                                     boost::posix_time::milliseconds(60000),
                                     boost::bind(&Authentication::SignerDone,
                                                 this, dependent_op_status));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("Authentication::CreateSigPkt (%i): %s\n", packet_type, e.what());
#endif
      success = false;
    }
    success = (dependent_op_status == kSucceeded);
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
  if (packet_type == MPID) {
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

  // Store packet
  VoidFuncOneInt functor = boost::bind(
      &Authentication::StoreOrDeletePacketCallback, this, _1, packet_type, true,
      attempt, op_status);
  store_manager_->StorePacket(sig_packet->name(), sig_packet->value(),
                              packet_type, PRIVATE, "", functor);
}

void Authentication::StoreOrDeletePacketCallback(
    const ReturnCode &return_code,
    const passport::PacketType &packet_type,
    bool storing,
    boost::uint8_t attempt,
    OpStatus *op_status) {
  bool is_last_attempt = (storing && (attempt == kMaxStoreAttempts_ - 1)) ||
                         (!storing && (atempt == kMaxDeleteAttempts_ - 1))
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
             " more retries.\n", packet_type, dbg.c_str());
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
    result = StorePacket(mid->name(), mid->value(), MID, "");
    if (result == kSuccess)
      result = StorePacket(tmid->name(), tmid->value(), TMID, "");
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

void Authentication::SaveSession(const std::string &serialised_data_atlas,
                                 const VoidFuncOneInt &functor) {
  boost::shared_ptr<SaveSessionData>
      save_session_data(new SaveSessionData(functor, true));

  std::string mid_old_value, smid_old_value;
  boost::shared_ptr<passport::MidPacket> updated_mid, updated_smid;
  boost::shared_ptr<passport::TmidPacket> new_tmid, tmid_for_deletion;
  int result = passport_->UpdateUserData(serialised_data_atlas, &mid_old_value,
      &smid_old_value, updated_mid, updated_smid, new_tmid, tmid_for_deletion);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::SaveSession: failed UpdateUserData.\n");
#endif
    return kAuthenticationError;
  }
// TODO(Fraser#5#): 2010-10-18 - Have method for retrying for MID and SMID
//                               failures independently.

  // Update or store SMID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                        this, _1, updated_smid,
                                        save_session_data);
  if (smid_old_value.empty()) {
    store_manager_->StorePacket(updated_smid->name(), updated_smid->value(),
                                SMID, PRIVATE, "", callback);
  } else {
    store_manager_->UpdatePacket(updated_smid->name(), smid_old_value,
                                 updated_smid->value(), SMID, PRIVATE, "",
                                 callback);
  }

  // Update MID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         updated_mid, save_session_data);
  store_manager_->UpdatePacket(updated_mid->name(), mid_old_value,
                               updated_mid->value(), MID, PRIVATE, "",
                               callback);

  // Store new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_tmid, save_session_data);
  store_manager_->StorePacket(new_tmid->name(), new_tmid->value(), TMID,
                              PRIVATE, "", callback);

  // Delete old STMID
  if (tmid_for_deletion.get()) {
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           tmid_for_deletion, save_session_data);
    std::vector<std::string> values(1, tmid_for_deletion->value());
    store_manager_->DeletePacket(tmid_for_deletion->name(), values, TMID,
                                 PRIVATE, "", callback);
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
  if (return_code != kSuccess) {
#ifdef DEBUG
    printf("Authentication::SaveSessionCallback (%i): Return Code %i\n",
           packet_type, return_code);
#endif
    op_status = kFailed;
  }
  boost::mutex::scoped_lock lock(mutex_);
  switch (packet->packet_type()) {
    case MID:
      save_session_data->process_mid = op_status;
      break;
    case SMID:
      save_session_data->process_smid = op_status;
      break;
    case TMID:
      save_session_data->process_tmid = op_status;
      break;
    case STMID:
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
    if (regular_save_session)
      save_session_data->functor(kFailedToDeleteOldTmid);
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
              boost::posix_time::milliseconds(300000),
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
    success = cond_var_.timed_wait(lock,boost::posix_time::milliseconds(60000),
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
    success = cond_var_.timed_wait(lock,boost::posix_time::milliseconds(120000),
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
                                     boost::posix_time::milliseconds(60000),
                                     boost::bind(&Authentication::SignerDone,
                                                 this, dependent_op_status));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("Authentication::DeletePacket (%i): %s\n", packet_type, e.what());
#endif
      success = false;
    }
    success = (dependent_op_status == kSucceeded);
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
// TODO(Fraser#5#): 2010-10-18 - Have method for retrying failures independently

  int store_result(kPendingResult);
  VoidFuncOneInt store_functor = boost::bind(&Authentication::PacketOpCallback,
                                             this, _1, &store_result);
  boost::shared_ptr<SaveSessionData>
      save_new_packets(new SaveSessionData(store_functor, false));

  // Store new MID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                        this, _1, new_mid, save_new_packets);
  store_manager_->StorePacket(new_mid->name(), new_mid->value(), MID, PRIVATE,
                              "", callback);
  // Store new SMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_smid, save_new_packets);
  store_manager_->StorePacket(new_smid->name(), new_smid->value(), SMID,
                              PRIVATE, "", callback);
  // Store new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_tmid, save_new_packets);
  store_manager_->StorePacket(new_tmid->name(), new_tmid->value(), TMID,
                              PRIVATE, "", callback);
  // Store new STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         new_stmid, save_new_packets);
  store_manager_->StorePacket(new_stmid->name(), new_stmid->value(), TMID,
                              PRIVATE, "", callback);

  // Wait for storing to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(300000),
              boost::bind(&Authentication::PacketOpDone, this, &store_result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: storing: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: timed out storing.\n");
#endif
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  int delete_result(kPendingResult);
  VoidFuncOneInt delete_functor = boost::bind(&Authentication::PacketOpCallback,
                                             this, _1, &delete_result);
  boost::shared_ptr<SaveSessionData>
      delete_old_packets(new SaveSessionData(delete_functor, false));

  // Delete old MID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         mid_for_deletion, delete_old_packets);
  std::vector<std::string> values(1, mid_for_deletion->value());
  store_manager_->DeletePacket(mid_for_deletion->name(), values, MID, PRIVATE,
                               "", callback);
  // Delete old SMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         smid_for_deletion, delete_old_packets);
  values.assign(1, smid_for_deletion->value());
  store_manager_->DeletePacket(smid_for_deletion->name(), values, SMID, PRIVATE,
                               "", callback);
  // Delete old TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         tmid_for_deletion, delete_old_packets);
  values.assign(1, tmid_for_deletion->value());
  store_manager_->DeletePacket(tmid_for_deletion->name(), values, TMID, PRIVATE,
                               "", callback);
  // Delete old STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         stmid_for_deletion, delete_old_packets);
  values.assign(1, stmid_for_deletion->value());
  store_manager_->DeletePacket(stmid_for_deletion->name(), values, TMID,
                               PRIVATE, "", callback);

  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(300000),
              boost::bind(&Authentication::PacketOpDone, this, &delete_result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: deleting: %s\n", e.what());
#endif
    success = false;
  }
  if (!success) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: timed out deleting.\n");
#endif
  }
  // Result of deletions not considered here.
  return store_result;
}








int Authentication::ChangePassword(const std::string &serialised_data_atlas,
                                   const std::string &new_password) {
  std::string old_password = session_singleton_->Password();
  session_singleton_->SetPassword(new_password);
  if (SaveSession(serialised_data_atlas) == kSuccess) {
    return kSuccess;
  } else {
    session_singleton_->SetPassword(old_password);
    return kAuthenticationError;
  }
}

std::string Authentication::CreateSignaturePackets(const PacketType &type_da,
                                                   std::string *public_key) {
  PacketParams params;
  crypto::RsaKeyPair kp;
  while (!crypto_key_pairs_.GetKeyPair(&kp)) {
    kp.ClearKeys();
    crypto_key_pairs_.StartToCreateKeyPairs(kNoOfSystemPackets);
  }
  boost::shared_ptr<Packet> sigPacket(PacketFactory::Factory(type_da));
  params["publicKey"] = kp.public_key();
  params["privateKey"] = kp.private_key();
  PacketParams result = sigPacket->Create(params);

  while (!store_manager_->KeyUnique(boost::any_cast<std::string>(result["name"]), false)) {
    kp.ClearKeys();
    while (!crypto_key_pairs_.GetKeyPair(&kp)) {
      kp.ClearKeys();
      crypto_key_pairs_.StartToCreateKeyPairs(kNoOfSystemPackets);
    }
    params["publicKey"] = kp.public_key();
    params["privateKey"] = kp.private_key();
    result = sigPacket->Create(params);
  }

  session_singleton_->AddKey(type_da,
              boost::any_cast<std::string>(result["name"]),
              boost::any_cast<std::string>(result["privateKey"]),
              boost::any_cast<std::string>(result["publicKey"]),
              "");

  if (StorePacket(boost::any_cast<std::string>(result["name"]),
                  boost::any_cast<std::string>(result["publicKey"]), type_da,
                  "")
      != kSuccess) {
    session_singleton_->RemoveKey(type_da);
    return "";
  }

  *public_key = boost::any_cast<std::string>(result["publicKey"]);
  return boost::any_cast<std::string>(result["privateKey"]);
}

bool Authentication::CheckUsername(const std::string &username) {
  std::string username_ = UtilsTrim(boost::lexical_cast<char*>(username));
  return (username_.length() >= 4);
}

bool Authentication::CheckPin(const std::string &pin) {
  std::string pin_ = UtilsTrim(boost::lexical_cast<char*>(pin));
  if (pin_ == "0000")
    return false;
  boost::regex re("\\d{4}");
  return boost::regex_match(pin_, re);
}

bool Authentication::CheckPassword(const std::string &password) {
  std::string password_ = UtilsTrim(boost::lexical_cast<char*>(password));
  return (password_.length() >= 4);
}

int Authentication::PublicUsernamePublicKey(const std::string &public_username,
                                            std::string *public_key) {
  PacketParams params;
  params["publicname"] = public_username;
  crypto::RsaKeyPair kp;
  boost::shared_ptr<Packet> mpidPacket(PacketFactory::Factory(MPID));

  std::vector<std::string> packet_content;
  int result = store_manager_->LoadPacket(mpidPacket->PacketName(params),
                                         &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kUserDoesntExist;
  std::string ser_generic_packet = packet_content[0];
  PacketParams mpid_result = mpidPacket->GetData(ser_generic_packet,
      PacketParams());

  std::string data(boost::any_cast<std::string>(mpid_result["data"]));

  if (data.empty()) {
    return kAuthenticationError;  // Packet corrupt
  }

  *public_key = data;

  return kSuccess;
}

void Authentication::CreateMSIDPacket(kad::VoidFunctorOneString cb) {
  PacketParams params;
  crypto::RsaKeyPair kp;
  while (!crypto_key_pairs_.GetKeyPair(&kp)) {
    kp.ClearKeys();
    crypto_key_pairs_.StartToCreateKeyPairs(kNoOfSystemPackets);
  }
  boost::shared_ptr<Packet> sigPacket(PacketFactory::Factory(MSID));
  params["publicKey"] = kp.public_key();
  params["privateKey"] = kp.private_key();
  PacketParams result = sigPacket->Create(params);

  int count = 0;
  while (!store_manager_->KeyUnique(boost::any_cast<std::string>(result["name"]),
         false) && count < 10) {
    kp.ClearKeys();
    while (!crypto_key_pairs_.GetKeyPair(&kp)) {
      kp.ClearKeys();
      crypto_key_pairs_.StartToCreateKeyPairs(kNoOfSystemPackets);
    }
    params["publicKey"] = kp.public_key();
    params["privateKey"] = kp.private_key();
    ++count;
  }

  if (count > 9) {
    CreateMSIDResult local_result;
    local_result.set_result(kNack);
    std::string ser_local_result;
    local_result.SerializeToString(&ser_local_result);
    cb(ser_local_result);
    return;
  }

  std::vector<boost::uint32_t> share_stats(2, 0);
  std::vector<std::string> atts;
  atts.push_back(boost::any_cast<std::string>(result["name"]));
  atts.push_back(boost::any_cast<std::string>(result["name"]));
  atts.push_back(boost::any_cast<std::string>(result["publicKey"]));
  atts.push_back(boost::any_cast<std::string>(result["privateKey"]));
  int n = session_singleton_->AddPrivateShare(atts, share_stats, NULL);

  n = StorePacket(boost::any_cast<std::string>(result["name"]),
      boost::any_cast<std::string>(result["publicKey"]), MSID,
      boost::any_cast<std::string>(result["name"]));
  session_singleton_->DeletePrivateShare(atts[0], 0);

  StoreChunkResponse result_msg;
  CreateMSIDResult local_result;
  std::string str_local_result;
  if (n != 0) {
    local_result.set_result(kNack);
  } else {
    local_result.set_result(kAck);
    local_result.set_private_key(boost::any_cast<std::string>(
        result["privateKey"]));
    local_result.set_public_key(boost::any_cast<std::string>(
        result["publicKey"]));
    local_result.set_name(boost::any_cast<std::string>(result["name"]));
  }
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

int Authentication::StorePacket(const std::string &packet_name,
                                const std::string &value,
                                const PacketType &type,
                                const std::string &msid) {
// TODO(Fraser#5#): 2010-01-28 - Use callbacks properly to allow several stores
//                               to happen concurrently.
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  store_manager_->StorePacket(packet_name, value, type, PRIVATE_SHARE, msid,
                              functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock, boost::posix_time::milliseconds(60000),
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

int Authentication::DeletePacket(const std::string &packet_name,
                                 const std::string &value,
                                 const PacketType &type) {
// TODO(Fraser#5#): 2010-01-28 - Use callbacks properly to allow several deletes
//                               to happen concurrently.
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  std::vector<std::string> values;
  if (!value.empty())
    values.push_back(value);
  store_manager_->DeletePacket(packet_name, values, type, PRIVATE, "", functor);
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock, boost::posix_time::milliseconds(60000),
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

void Authentication::PacketOpCallback(const ReturnCode &return_code,
                                      int *op_result) {
  boost::mutex::scoped_lock lock(mutex_);
  *op_result = return_code;
  cond_var_->notify_all();
}

std::string Authentication::EncryptedDataMidSmid(boost::uint32_t rid) {
  std::string salt = crypto_.Hash(session_singleton_->Pin() + session_singleton_->Username(), "",
                                  crypto::STRING_STRING, false);
  if (salt.empty())
    return "";
  std::string password = crypto_.SecurePassword(session_singleton_->Username(), salt,
                         boost::lexical_cast<boost::uint16_t>(session_singleton_->Pin()));
  return crypto_.SymmEncrypt(boost::lexical_cast<std::string>(rid), "",
                             crypto::STRING_STRING, password);
}

void Authentication::CreateSystemPacketsCallback(const ReturnCode &return_code) {
  system_packets_result_ = return_code;
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

char *Authentication::UtilsTrim(char *szSource) {
  return UtilsTrimLeft(UtilsTrimRight(UtilsTrimLeft(szSource)));
}
*/

}  // namespace maidsafe
