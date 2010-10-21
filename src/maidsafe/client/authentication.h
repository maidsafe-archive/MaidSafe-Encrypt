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

#ifndef MAIDSAFE_CLIENT_AUTHENTICATION_H_
#define MAIDSAFE_CLIENT_AUTHENTICATION_H_

#include <boost/cstdint.hpp>

#include <string>
#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/common/returncodes.h"

namespace maidsafe {

class StoreManagerInterface;
class SessionSingleton;

class Authentication {
 public:
  Authentication() : store_manager_(),
                     session_singleton_(),
                     passport_(),
                     mutex_(),
                     cond_var_(),
                     tmid_op_status_(kPendingMid),
                     stmid_op_status_(kPendingMid),
                     encrypted_tmid_(),
                     encrypted_stmid_(),
                     public_name_(),
                     kMaxStoreAttempts_(2),
                     kMaxDeleteAttempts_(2),
                     kSingleOpTimeout_(10000) {}
  ~Authentication() {}
  void Init(const boost::uint16_t &crypto_key_buffer_count,
            boost::shared_ptr<StoreManagerInterface> storemanager,
            boost::shared_ptr<passport::Passport> passport);
  int GetUserInfo(const std::string &username, const std::string &pin);
  int GetUserData(const std::string &password,
                  std::string *serialised_data_atlas);
  int CreateUserSysPackets(const std::string &username,
                           const std::string &pin);
  int CreateTmidPacket(const std::string &username,
                       const std::string &pin,
                       const std::string &password,
                       const std::string &serialised_datamap);
  int CreateMsidPacket(std::string *msid_name,
                       std::string *msid_public_key,
                       std::string *msid_private_key);
  void SaveSession(const std::string &serialised_data_atlas,
                   const VoidFuncOneInt &functor);
  int SaveSession(const std::string &serialised_data_atlas);
  int CreatePublicName(const std::string &public_name);
  int RemoveMe();
  int ChangeUsername(const std::string &serialised_data_atlas,
                     const std::string &new_username);
  int ChangePin(const std::string &serialised_data_atlas,
                const std::string &new_pin);
  int ChangePassword(const std::string &serialised_data_atlas,
                     const std::string &new_password);
 private:
  enum OpStatus {
    kSucceeded,
    kFailed,
    kPending,
    kPendingMid,
    kPendingTmid,
    kNoUser
  };
  enum SaveSessionOpType { kRegular, kSaveNew, kDeleteOld, kUpdate, kUnique };
  struct SaveSessionData {
    SaveSessionData(VoidFuncOneInt func, SaveSessionOpType op_t)
        : process_mid(kPending),
          process_smid(kPending),
          process_tmid(kPending),
          process_stmid(kPending),
          functor(func),
          op_type(op_t) {}
    OpStatus process_mid, process_smid, process_tmid, process_stmid;
    VoidFuncOneInt functor;
    SaveSessionOpType op_type;
  };
  Authentication &operator=(const Authentication&);
  Authentication(const Authentication&);
  void GetMidTmidCallback(const std::vector<std::string> &values,
                          const ReturnCode &return_code,
                          bool surrogate);
  // Function waits until dependent_op_status != kPending or timeout before
  // starting
  void CreateSignaturePacket(const passport::PacketType &packet_type,
                             boost::uint8_t attempt,
                             OpStatus *op_status,
                             OpStatus *dependent_op_status);
  void PacketUniqueCallback(const ReturnCode &return_code,
                            boost::shared_ptr<pki::Packet> packet,
                            boost::uint8_t attempt,
                            OpStatus *op_status);
  void StoreOrDeletePacketCallback(const ReturnCode &return_code,
                                   const passport::PacketType &packet_type,
                                   bool storing,
                                   boost::uint8_t attempt,
                                   OpStatus *op_status);
  void SaveSessionCallback(
      const ReturnCode &return_code,
      boost::shared_ptr<pki::Packet> packet,
      boost::shared_ptr<SaveSessionData> save_session_data);
  void DeletePacket(const passport::PacketType &packet_type,
                    boost::uint8_t attempt,
                    OpStatus *op_status,
                    OpStatus *dependent_op_status);
  int ChangeUserData(const std::string &serialised_data_atlas,
                     const std::string &new_username,
                     const std::string &new_pin);
  bool CheckUsername(const std::string &username);
  bool CheckPin(std::string pin);
  bool CheckPassword(const std::string &password);

  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool TmidOpDone() {
    return (tmid_op_status_ == kSucceeded || tmid_op_status_ == kNoUser ||
            tmid_op_status_ == kFailed);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool StmidOpDone() {
    return (stmid_op_status_ == kSucceeded || stmid_op_status_ == kNoUser ||
            stmid_op_status_ == kFailed);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SignerDone(OpStatus *op_status) { return *op_status != kPending; }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SystemPacketsOpDone(const OpStatus &op_status1,
                           const OpStatus &op_status2) {
    return (op_status1 != kPending) && (op_status2 != kPending);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SystemPacketsOpDone(const OpStatus &op_status1,
                           const OpStatus &op_status2,
                           const OpStatus &op_status3) {
    return SystemPacketsOpDone(op_status1, op_status2) &&
           (op_status3 != kPending);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SystemPacketsOpDone(const OpStatus &op_status1,
                           const OpStatus &op_status2,
                           const OpStatus &op_status3,
                           const OpStatus &op_status4,
                           const OpStatus &op_status5) {
    return SystemPacketsOpDone(op_status1, op_status2, op_status3) &&
           SystemPacketsOpDone(op_status4, op_status5);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool PacketOpDone(int *return_code) { return *return_code != kPendingResult; }
  int StorePacket(boost::shared_ptr<pki::Packet> packet, bool check_uniqueness);
  int DeletePacket(boost::shared_ptr<pki::Packet> packet);
  int PacketUnique(boost::shared_ptr<pki::Packet> packet);
  void PacketOpCallback(const ReturnCode &return_code, int *op_result);
  char *UtilsTrimRight(char *szSource);
  char *UtilsTrimLeft(char *szSource);
  std::string UtilsTrim(std::string source);
  boost::shared_ptr<StoreManagerInterface> store_manager_;
  SessionSingleton *session_singleton_;
  boost::shared_ptr<passport::Passport> passport_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  OpStatus tmid_op_status_, stmid_op_status_;
  std::string encrypted_tmid_, encrypted_stmid_, public_name_;
  const boost::uint8_t kMaxStoreAttempts_, kMaxDeleteAttempts_;
  const int kSingleOpTimeout_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_AUTHENTICATION_H_
