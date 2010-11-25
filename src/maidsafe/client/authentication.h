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
#include <boost/tr1/memory.hpp>
#include <maidsafe/passport/passport.h>

#include <string>
#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/returncodes.h"

namespace maidsafe {

namespace test {
class AuthenticationTest_FUNC_MAID_CreatePublicName_Test;
class AuthenticationTest_FUNC_MAID_CreateMSIDPacket_Test;
class AuthenticationTest_FUNC_MAID_NET_CreatePublicName_Test;
class AuthenticationTest_FUNC_MAID_NET_CreateMSIDPacket_Test;
class ClientControllerTest;
}  // namespace test

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
                     kSingleOpTimeout_(10000) {}
  ~Authentication();
  // Used to intialise passport_ in all cases.
  void Init(boost::shared_ptr<StoreManagerInterface> sm);
  // Used to intialise passport_ in all cases.
  int GetUserInfo(const std::string &username, const std::string &pin);
  // Used when creating a new user.
  int CreateUserSysPackets(const std::string &username,
                           const std::string &pin);
  // Used when creating a new user.
  int CreateTmidPacket(const std::string &username,
                       const std::string &pin,
                       const std::string &password,
                       const std::string &serialised_datamap);
  void SaveSession(const std::string &serialised_data_atlas,
                   const VoidFuncOneInt &functor);
  int SaveSession(const std::string &serialised_data_atlas);
  // Used when logging in.
  int GetUserData(const std::string &password,
                  std::string *serialised_data_atlas);
  int CreateMsidPacket(std::string *msid_name,
                       std::string *msid_public_key,
                       std::string *msid_private_key);
  int CreatePublicName(const std::string &public_name);
  int RemoveMe();
  int ChangeUsername(const std::string &serialised_data_atlas,
                     const std::string &new_username);
  int ChangePin(const std::string &serialised_data_atlas,
                const std::string &new_pin);
  int ChangePassword(const std::string &serialised_data_atlas,
                     const std::string &new_password);
  int PublicUsernamePublicKey(const std::string &public_username,
                              std::string *public_key);
 private:
  enum OpStatus {
    kSucceeded,
    kFailed,
    kNotUnique,
    kPending,
    kPendingMid,
    kPendingTmid,
    kNoUser
  };
  enum SaveSessionOpType { kRegular, kSaveNew, kDeleteOld, kUpdate, kIsUnique };
  struct SaveSessionData {
    SaveSessionData(VoidFuncOneInt func, SaveSessionOpType op_t)
        : mid(new passport::MidPacket), smid(new passport::MidPacket),
          tmid(new passport::TmidPacket), stmid(new passport::TmidPacket),
          process_mid(kPending), process_smid(kPending),
          process_tmid(kPending), process_stmid(kPending),
          functor(func), op_type(op_t) {}
    std::tr1::shared_ptr<passport::MidPacket> mid, smid;
    std::tr1::shared_ptr<passport::TmidPacket> tmid, stmid;
    OpStatus process_mid, process_smid, process_tmid, process_stmid;
    VoidFuncOneInt functor;
    SaveSessionOpType op_type;
  };
  friend class test::AuthenticationTest_FUNC_MAID_CreatePublicName_Test;
  friend class test::AuthenticationTest_FUNC_MAID_CreateMSIDPacket_Test;
  friend class test::AuthenticationTest_FUNC_MAID_NET_CreatePublicName_Test;
  friend class test::AuthenticationTest_FUNC_MAID_NET_CreateMSIDPacket_Test;
  friend class test::ClientControllerTest;

  Authentication &operator=(const Authentication&);
  Authentication(const Authentication&);
  void GetMidTmidCallback(const std::vector<std::string> &values,
                          const ReturnCode &return_code,
                          bool surrogate);
  // Function waits until dependent_op_status != kPending or timeout before
  // starting
  void CreateSignaturePacket(const passport::PacketType &packet_type,
                             const std::string &public_name,
                             OpStatus *op_status,
                             OpStatus *dependent_op_status);
  void SignaturePacketUniqueCallback(
      const ReturnCode &return_code,
      std::tr1::shared_ptr<passport::SignaturePacket> packet,
      OpStatus *op_status);
  void SignaturePacketStoreCallback(
    const ReturnCode &return_code,
    std::tr1::shared_ptr<passport::SignaturePacket> packet,
    OpStatus *op_status);
  void SaveSessionCallback(
      const ReturnCode &return_code,
      std::tr1::shared_ptr<pki::Packet> packet,
      std::tr1::shared_ptr<SaveSessionData> save_session_data);
  void DeletePacket(const passport::PacketType &packet_type,
                    OpStatus *op_status,
                    OpStatus *dependent_op_status);
  void DeletePacketCallback(const ReturnCode &return_code,
                            const passport::PacketType &packet_type,
                            OpStatus *op_status);
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
  bool SystemPacketsOpDone(OpStatus *op_status1, OpStatus *op_status2) {
    return (*op_status1 != kPending) && (*op_status2 != kPending);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SystemPacketsOpDone(OpStatus *op_status1,
                           OpStatus *op_status2,
                           OpStatus *op_status3) {
    return SystemPacketsOpDone(op_status1, op_status2) &&
           (*op_status3 != kPending);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool SystemPacketsOpDone(OpStatus *op_status1,
                           OpStatus *op_status2,
                           OpStatus *op_status3,
                           OpStatus *op_status4,
                           OpStatus *op_status5) {
    return SystemPacketsOpDone(op_status1, op_status2, op_status3) &&
           SystemPacketsOpDone(op_status4, op_status5);
  }
  // Designed to be called as functor in timed_wait - user_info mutex locked
  bool PacketOpDone(int *return_code) { return *return_code != kPendingResult; }
  int StorePacket(std::tr1::shared_ptr<pki::Packet> packet,
                  bool check_uniqueness);
  int DeletePacket(std::tr1::shared_ptr<pki::Packet> packet);
  int PacketUnique(std::tr1::shared_ptr<pki::Packet> packet);
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
  std::string encrypted_tmid_, encrypted_stmid_;
  const int kSingleOpTimeout_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_AUTHENTICATION_H_
