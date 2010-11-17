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

#include "maidsafe/common/commonutils.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

Authentication::~Authentication() {
  bool tmid_success, stmid_success;
  try {
    boost::mutex::scoped_lock lock(mutex_);
    tmid_success = cond_var_.timed_wait(lock,
                   boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
                   boost::bind(&Authentication::TmidOpDone, this));
    stmid_success = cond_var_.timed_wait(lock,
                    boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
                    boost::bind(&Authentication::StmidOpDone, this));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication dtor: %s\n", e.what());
#endif
  }
#ifdef DEBUG
  if (!tmid_success)
    printf("Authentication dtor: timed out waiting for TMID.\n");
  if (!stmid_success)
    printf("Authentication dtor: timed out waiting for STMID.\n");
#endif
}

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

  int result(kSuccess);
  GenericPacket packet;
  if (!packet.ParseFromString(values.at(0)) || packet.data().empty())
    result = kBadPacket;
  if (op_status == kPendingMid) {
    std::string tmid_name;
    if (result == kSuccess)
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
      if (result == kSuccess) {
        encrypted_stmid_ = packet.data();
        stmid_op_status_ = kSucceeded;
      } else {
        stmid_op_status_ = kFailed;
      }
      if (tmid_op_status_ == kFailed)
        cond_var_.notify_all();
    } else {
      if (result == kSuccess) {
        encrypted_tmid_ = packet.data();
        tmid_op_status_ = kSucceeded;
      } else {
        tmid_op_status_ = kFailed;
      }
      cond_var_.notify_all();
    }
  }
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
    return kAuthenticationError;
  }
  session_singleton_->SetUsername(username);
  session_singleton_->SetPin(pin);

  OpStatus anmaid_status(kPending);
  CreateSignaturePacket(passport::ANMAID, &anmaid_status, NULL);

  OpStatus anmid_status(kPending);
  CreateSignaturePacket(passport::ANMID, &anmid_status, NULL);

  OpStatus ansmid_status(kPending);
  CreateSignaturePacket(passport::ANSMID, &ansmid_status, NULL);

  OpStatus antmid_status(kPending);
  CreateSignaturePacket(passport::ANTMID, &antmid_status, NULL);

// TODO(Fraser#5#): 2010-10-18 - Thread these next two?
  OpStatus maid_status(kPending);
  CreateSignaturePacket(passport::MAID, &maid_status, &anmaid_status);

  OpStatus pmid_status(kPending);
  CreateSignaturePacket(passport::PMID, &pmid_status, &maid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(5 * kSingleOpTimeout_),
              boost::bind(&Authentication::SystemPacketsOpDone, this,
                          &pmid_status, &anmid_status, &antmid_status));
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
  std::tr1::shared_ptr<passport::SignaturePacket>
      sig_packet(new passport::SignaturePacket);
  int result(kPendingResult);
  if (packet_type == passport::MPID)
    result = passport_->InitialiseMpid(session_singleton_->PublicUsername(),
                                       sig_packet);
  else
    result = passport_->InitialiseSignaturePacket(packet_type, sig_packet);
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
  VoidFuncOneInt f = boost::bind(&Authentication::SignaturePacketUniqueCallback,
                                 this, _1, sig_packet, op_status);
  store_manager_->KeyUnique(sig_packet->name(), false, f);
}

void Authentication::SignaturePacketUniqueCallback(
    const ReturnCode &return_code,
    std::tr1::shared_ptr<passport::SignaturePacket> packet,
    OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  if (return_code != kKeyUnique) {
    boost::mutex::scoped_lock lock(mutex_);
#ifdef DEBUG
    printf("Authentication::SignaturePacketUniqueCbk (%i): Failed to store.\n",
            packet_type);
#endif
    *op_status = kNotUnique;
    passport_->RevertSignaturePacket(packet_type);
    cond_var_.notify_all();
    return;
  }

  // Store packet
  VoidFuncOneInt functor = boost::bind(
      &Authentication::SignaturePacketStoreCallback, this, _1, packet,
      op_status);
  store_manager_->StorePacket(packet->name(), packet->value(), packet_type,
                              PRIVATE, "", functor);
}

void Authentication::SignaturePacketStoreCallback(
    const ReturnCode &return_code,
    std::tr1::shared_ptr<passport::SignaturePacket> packet,
    OpStatus *op_status) {
  passport::PacketType packet_type =
      static_cast<passport::PacketType>(packet->packet_type());
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
    passport_->ConfirmSignaturePacket(packet);
  } else {
#ifdef DEBUG
    printf("Authentication::SignaturePacketStoreCbk (%i): Failed to delete.\n",
            packet_type);
#endif
    *op_status = kFailed;
    passport_->RevertSignaturePacket(packet_type);
  }
  cond_var_.notify_all();
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

  std::tr1::shared_ptr<passport::MidPacket> mid(new passport::MidPacket);
  std::tr1::shared_ptr<passport::MidPacket> smid(new passport::MidPacket);
  std::tr1::shared_ptr<passport::TmidPacket> tmid(new passport::TmidPacket);
  int result(kPendingResult);
  const boost::uint8_t kMaxAttempts(3);
  boost::uint8_t attempt(0);
  while ((result != kSuccess) && (attempt < kMaxAttempts)) {
    result = passport_->SetNewUserData(password, serialised_datamap, mid, smid,
                                       tmid);
    if (result != kSuccess) {
#ifdef DEBUG
      printf("Authentication::CreateTmidPacket: failed init.\n");
#endif
      return kAuthenticationError;
    }
    bool unique((PacketUnique(mid) == kKeyUnique) &&
                (PacketUnique(smid) == kKeyUnique) &&
                (PacketUnique(tmid) == kKeyUnique));
    if (!unique) {
#ifdef DEBUG
      printf("Authentication::CreateTmidPacket: MID, SMID or TMID exists.\n");
#endif
      ++attempt;
      result = kKeyNotUnique;
      continue;
    }
  }
  result = StorePacket(mid, false);
  if (result == kSuccess)
    result = StorePacket(smid, false);
  if (result == kSuccess)
    result = StorePacket(tmid, false);

  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::CreateTmidPacket: failed.\n");
#endif
    return kAuthenticationError;
  } else {
    passport_->ConfirmNewUserData(mid, smid, tmid);
    session_singleton_->SetPassword(password);
    return kSuccess;
  }
}

void Authentication::SaveSession(const std::string &serialised_data_atlas,
                                 const VoidFuncOneInt &functor) {
  std::tr1::shared_ptr<SaveSessionData>
      save_session_data(new SaveSessionData(functor, kRegular));

  std::string mid_old_value, smid_old_value;
  int result(passport_->UpdateMasterData(serialised_data_atlas, &mid_old_value,
      &smid_old_value, save_session_data->mid, save_session_data->smid,
      save_session_data->tmid, save_session_data->stmid));
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::SaveSession: failed UpdateUserData.\n");
#endif
    functor(kAuthenticationError);
    return;
  }

  // Update or store SMID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                                        this, _1, save_session_data->smid,
                                        save_session_data);
  if (smid_old_value.empty()) {
    store_manager_->StorePacket(save_session_data->smid->name(),
                                save_session_data->smid->value(),
                                passport::SMID, PRIVATE, "", callback);
  } else if (smid_old_value != save_session_data->smid->value()) {
    store_manager_->UpdatePacket(save_session_data->smid->name(),
                                 smid_old_value,
                                 save_session_data->smid->value(),
                                 passport::SMID, PRIVATE, "", callback);
  } else {
    // Only time where old val == new val is first ever SaveSession as MID and
    // SMID are both created with the same RID.
    save_session_data->process_smid = kSucceeded;
  }

  // Update MID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_session_data->mid, save_session_data);
  store_manager_->UpdatePacket(save_session_data->mid->name(), mid_old_value,
                               save_session_data->mid->value(),
                               passport::MID, PRIVATE, "", callback);

  // Store new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_session_data->tmid, save_session_data);
  store_manager_->StorePacket(save_session_data->tmid->name(),
                              save_session_data->tmid->value(), passport::TMID,
                              PRIVATE, "", callback);

  // Delete old STMID
  if (save_session_data->stmid &&
      !save_session_data->stmid->username().empty()) {
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           save_session_data->stmid, save_session_data);
    std::vector<std::string> values(1, save_session_data->stmid->value());
    store_manager_->DeletePacket(save_session_data->stmid->name(), values,
                                 passport::TMID, PRIVATE, "", callback);
  } else {
    boost::mutex::scoped_lock lock(mutex_);
    save_session_data->process_stmid = kSucceeded;
  }
}

void Authentication::SaveSessionCallback(
    const ReturnCode &return_code,
    std::tr1::shared_ptr<pki::Packet> packet,
    std::tr1::shared_ptr<SaveSessionData> save_session_data) {
  OpStatus op_status(kSucceeded);
  if ((save_session_data->op_type == kIsUnique && return_code != kKeyUnique) ||
      (save_session_data->op_type != kIsUnique && return_code != kSuccess)) {
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
    passport_->RevertMasterDataUpdate();
    save_session_data->functor(kAuthenticationError);
    return;
  }
  if ((save_session_data->process_stmid == kFailed)) {
    lock.unlock();
    if (save_session_data->op_type == kRegular) {
      passport_->ConfirmMasterDataUpdate(save_session_data->mid,
          save_session_data->smid, save_session_data->tmid);
      save_session_data->functor(kFailedToDeleteOldPacket);
    } else {
      passport_->RevertMasterDataUpdate();
      save_session_data->functor(kAuthenticationError);
    }
    return;
  }
  lock.unlock();
  if (save_session_data->op_type == kRegular)
    passport_->ConfirmMasterDataUpdate(save_session_data->mid,
        save_session_data->smid, save_session_data->tmid);
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
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
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

int Authentication::GetUserData(const std::string &password,
                                std::string *serialised_data_atlas) {
  //  still have not recovered the tmid
  int result = passport_->GetUserData(password, false, encrypted_tmid_,
                                      serialised_data_atlas);
  encrypt::DataMap dm;
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

int Authentication::CreateMsidPacket(std::string *msid_name,
                                     std::string *msid_public_key,
                                     std::string *msid_private_key) {
  if (!msid_name || !msid_public_key || !msid_private_key)
    return kAuthenticationError;
  msid_name->clear();
  msid_public_key->clear();
  msid_private_key->clear();

  std::tr1::shared_ptr<passport::SignaturePacket>
      msid(new passport::SignaturePacket);
  std::vector<boost::uint32_t> share_stats(2, 0);
  int result = passport_->InitialiseSignaturePacket(passport::MSID, msid);
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

int Authentication::CreatePublicName(const std::string &public_name) {
  if (!session_singleton_->PublicUsername().empty()) {
#ifdef DEBUG
    printf("Authentication::CreatePublicName - Already set.\n");
#endif
    return kPublicUsernameAlreadySet;
  }

  OpStatus anmpid_status(kSucceeded);
  if (!passport_->GetPacket(passport::ANMPID, true)) {
    anmpid_status = kPending;
    CreateSignaturePacket(passport::ANMPID, &anmpid_status, NULL);
  }

// TODO(Fraser#5#): 2010-10-18 - Thread this?
  OpStatus mpid_status(kPending);
  CreateSignaturePacket(passport::MPID, &mpid_status, &anmpid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(2 * kSingleOpTimeout_),
              boost::bind(&Authentication::SystemPacketsOpDone, this,
                          &mpid_status, &anmpid_status));
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
    session_singleton_->SetPublicUsername(public_name);
    return kSuccess;
  } else if (mpid_status == kNotUnique) {
    return kPublicUsernameExists;
  } else {
    return kAuthenticationError;
  }
}

int Authentication::RemoveMe() {
// TODO(Fraser#5#): 2010-10-18 - Thread these?
  OpStatus pmid_status(kPending);
  DeletePacket(passport::PMID, &pmid_status, NULL);
  OpStatus maid_status(kPending);
  DeletePacket(passport::MAID, &maid_status, &pmid_status);
  OpStatus anmaid_status(kPending);
  DeletePacket(passport::ANMAID, &anmaid_status, &maid_status);

  OpStatus tmid_status(kPending);
  DeletePacket(passport::TMID, &tmid_status, NULL);
  OpStatus stmid_status(kPending);
  DeletePacket(passport::STMID, &stmid_status, &tmid_status);
  OpStatus antmid_status(kPending);
  DeletePacket(passport::ANTMID, &antmid_status, &stmid_status);

  OpStatus mid_status(kPending);
  DeletePacket(passport::MID, &mid_status, NULL);
  OpStatus anmid_status(kPending);
  DeletePacket(passport::ANMID, &anmid_status, &mid_status);

  OpStatus smid_status(kPending);
  DeletePacket(passport::SMID, &smid_status, NULL);
  OpStatus ansmid_status(kPending);
  DeletePacket(passport::ANSMID, &ansmid_status, &smid_status);

  OpStatus mpid_status(kPending);
  DeletePacket(passport::MPID, &mpid_status, NULL);
  OpStatus anmpid_status(kPending);
  DeletePacket(passport::ANMPID, &anmpid_status, &mpid_status);

  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(12 * kSingleOpTimeout_),
              boost::bind(&Authentication::SystemPacketsOpDone, this,
                          &anmaid_status, &antmid_status, &anmid_status,
                          &ansmid_status, &anmpid_status));
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
  std::tr1::shared_ptr<pki::Packet> packet(passport_->GetPacket(packet_type,
                                                                true));
  if (!packet) {
    boost::mutex::scoped_lock lock(mutex_);
    *op_status = kSucceeded;
    cond_var_.notify_all();
    return;
  }

  // Delete packet
  VoidFuncOneInt functor = boost::bind(
      &Authentication::DeletePacketCallback, this, _1, packet_type, op_status);
  std::vector<std::string> values(1, packet->value());
  store_manager_->DeletePacket(packet->name(), values, packet_type, PRIVATE, "",
                               functor);
}

void Authentication::DeletePacketCallback(
    const ReturnCode &return_code,
    const passport::PacketType &packet_type,
    OpStatus *op_status) {
  boost::mutex::scoped_lock lock(mutex_);
  if (return_code == kSuccess) {
    *op_status = kSucceeded;
    passport_->DeletePacket(packet_type);
  } else {
#ifdef DEBUG
    printf("Authentication::DeletePacketCallback (%i): Failed to delete.\n",
            packet_type);
#endif
    *op_status = kFailed;
  }
  cond_var_.notify_all();
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
  int uniqueness_result(kPendingResult);
  VoidFuncOneInt uniqueness_functor = boost::bind(
      &Authentication::PacketOpCallback, this, _1, &uniqueness_result);
  std::tr1::shared_ptr<SaveSessionData>
      save_new_packets(new SaveSessionData(uniqueness_functor, kIsUnique));

  int delete_result(kPendingResult);
  VoidFuncOneInt delete_functor = boost::bind(&Authentication::PacketOpCallback,
                                             this, _1, &delete_result);
  std::tr1::shared_ptr<SaveSessionData>
      delete_old_packets(new SaveSessionData(delete_functor, kDeleteOld));

  int result = passport_->ChangeUserData(new_username, new_pin,
               serialised_data_atlas, delete_old_packets->mid,
               delete_old_packets->smid, delete_old_packets->tmid,
               delete_old_packets->stmid, save_new_packets->mid,
               save_new_packets->smid, save_new_packets->tmid,
               save_new_packets->stmid);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: failed ChangeUserData.\n");
#endif
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Check new MID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                            this, _1, save_new_packets->mid, save_new_packets);
  store_manager_->KeyUnique(save_new_packets->mid->name(), false, callback);
  // Check new SMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_new_packets->smid, save_new_packets);
  store_manager_->KeyUnique(save_new_packets->smid->name(), false, callback);
  // Check new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_new_packets->tmid, save_new_packets);
  store_manager_->KeyUnique(save_new_packets->tmid->name(), false, callback);
  // Check new STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_new_packets->stmid, save_new_packets);
  store_manager_->KeyUnique(save_new_packets->stmid->name(), false, callback);

  // Wait for checking to complete
  bool success(true);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
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
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  if (uniqueness_result != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: non-unique packets.\n");
#endif
    passport_->RevertUserDataChange();
    return kUserExists;
  }

  int store_result(kPendingResult);
  VoidFuncOneInt store_functor = boost::bind(&Authentication::PacketOpCallback,
                                             this, _1, &store_result);
  save_new_packets->process_mid = kPending;
  save_new_packets->process_smid = kPending;
  save_new_packets->process_tmid = kPending;
  save_new_packets->process_stmid = kPending;
  save_new_packets->functor = store_functor;
  save_new_packets->op_type = kSaveNew;

  // Store new MID
  callback = boost::bind(&Authentication::SaveSessionCallback,
                         this, _1, save_new_packets->mid, save_new_packets);
  store_manager_->StorePacket(save_new_packets->mid->name(),
                              save_new_packets->mid->value(),
                              passport::MID, PRIVATE, "", callback);
  // Store new SMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_new_packets->smid, save_new_packets);
  store_manager_->StorePacket(save_new_packets->smid->name(),
                              save_new_packets->smid->value(),
                              passport::SMID, PRIVATE, "", callback);
  // Store new TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         save_new_packets->tmid, save_new_packets);
  store_manager_->StorePacket(save_new_packets->tmid->name(),
                              save_new_packets->tmid->value(),
                              passport::TMID, PRIVATE, "", callback);
  // Store new STMID
  if (save_new_packets->stmid->name() == save_new_packets->tmid->name()) {
    // This should only be the case for a new user where only one SaveSession
    // has been done.
    save_new_packets->process_stmid = kSucceeded;
  } else {
    callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                           save_new_packets->stmid, save_new_packets);
    store_manager_->StorePacket(save_new_packets->stmid->name(),
                                save_new_packets->stmid->value(),
                                passport::TMID, PRIVATE, "", callback);
  }

  // Wait for storing to complete
  success = true;
  try {
    boost::mutex::scoped_lock lock(mutex_);
    success = cond_var_.timed_wait(lock,
              boost::posix_time::milliseconds(4 * kSingleOpTimeout_),
              boost::bind(&Authentication::PacketOpDone, this,
                          &store_result));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: storing: %s\n", e.what());
#endif
    success = false;
  }
  if (store_result != kSuccess || !success) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: storing packets failed.\n");
#endif
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }

  // Prepare to delete old packets
  // Delete old MID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         delete_old_packets->mid, delete_old_packets);
  std::vector<std::string> values(1, delete_old_packets->mid->value());
  store_manager_->DeletePacket(delete_old_packets->mid->name(), values,
                               passport::MID, PRIVATE, "", callback);
  // Delete old SMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         delete_old_packets->smid, delete_old_packets);
  values.assign(1, delete_old_packets->smid->value());
  store_manager_->DeletePacket(delete_old_packets->smid->name(), values,
                               passport::SMID, PRIVATE, "", callback);
  // Delete old TMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         delete_old_packets->tmid, delete_old_packets);
  values.assign(1, delete_old_packets->tmid->value());
  store_manager_->DeletePacket(delete_old_packets->tmid->name(), values,
                               passport::TMID, PRIVATE, "", callback);
  // Delete old STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         delete_old_packets->stmid, delete_old_packets);
  values.assign(1, delete_old_packets->stmid->value());
  store_manager_->DeletePacket(delete_old_packets->stmid->name(), values,
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
  // Result of deletions not considered here.
  if (passport_->ConfirmUserDataChange(save_new_packets->mid,
                                       save_new_packets->smid,
                                       save_new_packets->tmid,
                                       save_new_packets->stmid) != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangeUserData: failed to confirm change.\n");
#endif
    passport_->RevertUserDataChange();
    return kAuthenticationError;
  }
  session_singleton_->SetUsername(new_username);
  session_singleton_->SetPin(new_pin);
  return kSuccess;
}

int Authentication::ChangePassword(const std::string &serialised_data_atlas,
                                   const std::string &new_password) {
  // Get updated packets
  int result(kPendingResult);
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  std::tr1::shared_ptr<SaveSessionData>
      update_packets(new SaveSessionData(functor, kUpdate));
  update_packets->process_mid = kSucceeded;
  update_packets->process_smid = kSucceeded;
  std::string tmid_old_value, stmid_old_value;
  int res = passport_->ChangePassword(new_password, serialised_data_atlas,
                                      &tmid_old_value, &stmid_old_value,
                                      update_packets->tmid,
                                      update_packets->stmid);
  if (res != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangePassword: failed ChangePassword.\n");
#endif
    passport_->RevertPasswordChange();
    return kAuthenticationError;
  }

  // Update TMID
  VoidFuncOneInt callback = boost::bind(&Authentication::SaveSessionCallback,
                            this, _1, update_packets->tmid, update_packets);
  store_manager_->UpdatePacket(update_packets->tmid->name(), tmid_old_value,
                               update_packets->tmid->value(), passport::TMID,
                               PRIVATE, "", callback);
  // Update STMID
  callback = boost::bind(&Authentication::SaveSessionCallback, this, _1,
                         update_packets->stmid, update_packets);
  store_manager_->UpdatePacket(update_packets->stmid->name(), stmid_old_value,
                               update_packets->stmid->value(), passport::TMID,
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
  if (result != kSuccess || !success) {
#ifdef DEBUG
    printf("Authentication::ChangePassword: timed out updating.\n");
#endif
    passport_->RevertPasswordChange();
    return kAuthenticationError;
  }
  if (passport_->ConfirmPasswordChange(update_packets->tmid,
                                       update_packets->stmid) != kSuccess) {
#ifdef DEBUG
    printf("Authentication::ChangePassword: failed to confirm change.\n");
#endif
    passport_->RevertPasswordChange();
    return kAuthenticationError;
  }
  session_singleton_->SetPassword(new_password);
  return kSuccess;
}

int Authentication::PublicUsernamePublicKey(const std::string &public_username,
                                            std::string *public_key) {
  std::string packet_name = SHA512String(public_username);
  std::vector<std::string> packet_content;
  int result = store_manager_->LoadPacket(packet_name, &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kUserDoesntExist;
  GenericPacket packet;
  if (!packet.ParseFromString(packet_content.at(0)) || !public_key)
    return kAuthenticationError;
  *public_key = packet.data();
  return kSuccess;
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

int Authentication::StorePacket(std::tr1::shared_ptr<pki::Packet> packet,
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

  result = kPendingResult;
  VoidFuncOneInt functor = boost::bind(&Authentication::PacketOpCallback, this,
                                       _1, &result);
  DirType dir_type(PRIVATE);
  std::string msid;
  if (packet->packet_type() == passport::MSID) {
    dir_type = PRIVATE_SHARE;
    msid = packet->name();
  }

  store_manager_->StorePacket(packet->name(), packet->value(),
      static_cast<passport::PacketType>(packet->packet_type()), dir_type, msid,
      functor);
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

int Authentication::DeletePacket(std::tr1::shared_ptr<pki::Packet> packet) {
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
  store_manager_->DeletePacket(packet->name(), values,
      static_cast<passport::PacketType>(packet->packet_type()), dir_type, msid,
      functor);
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

int Authentication::PacketUnique(std::tr1::shared_ptr<pki::Packet> packet) {
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
