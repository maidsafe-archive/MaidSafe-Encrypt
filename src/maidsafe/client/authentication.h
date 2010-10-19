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
//#include <boost/function.hpp>
//#include <boost/shared_ptr.hpp>
//#include <boost/thread/condition_variable.hpp>
//#include <boost/thread/mutex.hpp>
//#include <maidsafe/base/crypto.h>
//
//#include <list>
#include <string>
//#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/passport/passport.h"

//#include "maidsafe/common/packet.pb.h"
#include "maidsafe/common/returncodes.h"

namespace maidsafe {

class StoreManagerInterface;
class SessionSingleton;

struct FindSystemPacketData {
  FindSystemPacketData() : system_packet_creation_data(), packet_type() {}
  boost::shared_ptr<SystemPacketCreationData> system_packet_creation_data;
  passport::PacketType packet_type;
};

class Authentication {
 public:
  Authentication() : crypto_(),
                     store_manager_(),
                     session_singleton_(),
                     passport_(),
                     mutex_(),
                     cond_var_(),
                     tmid_op_status_(kPendingMid),
                     stmid_op_status(kPendingMid),
                     serialised_tmid_packet_(),
                     serialised_stmid_packet_(),
                     public_name_(),
                     kMaxStoreAttempts_(3),
                     kMaxDeleteAttempts_(2) {}
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






  int PublicUsernamePublicKey(const std::string &public_username,
                              std::string *public_key);
  void CreateMSIDPacket(kad::VoidFunctorOneString cb);
 private:
  enum OpStatus {
    kSucceeded,
    kFailed,
    kPending,
    kPendingMid,
    kPendingTmid,
    kNoUser
  };
  struct SaveSessionData {
    SaveSessionData(VoidFuncOneInt func, bool regular_save_sess)
        : process_mid(kPending),
          process_smid(kPending),
          process_tmid(kPending),
          process_stmid(kPending),
          functor(func),
          regular_save_session(regular_save_sess) {}
    OpStatus process_mid, process_smid, process_tmid, process_stmid;
    VoidFuncOneInt functor;
    bool regular_save_session;
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




  std::string CreateSignaturePackets(const PacketType &type_da,
                                     std::string *public_key);
  bool CheckUsername(const std::string &username);
  bool CheckPin(const std::string &pin);
  bool CheckPassword(const std::string &password);
  int StorePacket(const std::string &packet_name,
                  const std::string &value,
                  const PacketType &type,
                  const std::string &msid);
  // Unneccessary, but more efficient/faster to pass packet's value here
  int DeletePacket(const std::string &packet_name,
                   const std::string &value,
                   const PacketType &type);
  void PacketOpCallback(const ReturnCode &return_code, int *op_result);
  void CreateSystemPacketsCallback(const ReturnCode &return_code);
  std::string EncryptedDataMidSmid(boost::uint32_t rid);

  void UpdateSmidCallback(const ReturnCode &return_code,
                          boost::shared_ptr<SaveSessionData> ssd);
  void DeleteSmidTmidCallback(const ReturnCode &return_code,
                              boost::shared_ptr<SaveSessionData> ssd);
  void UpdateMidCallback(const ReturnCode &return_code,
                         boost::shared_ptr<SaveSessionData> ssd);
  void StoreMidTmidCallback(const ReturnCode &return_code,
                            boost::shared_ptr<SaveSessionData> ssd);
  char *UtilsTrimRight(char *szSource);
  char *UtilsTrimLeft(char *szSource);
  char *UtilsTrim(char *szSource);

  crypto::Crypto crypto_;
  boost::shared_ptr<StoreManagerInterface> store_manager_;
  SessionSingleton *session_singleton_;
  boost::shared_ptr<passport::Passport> passport_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  OpStatus tmid_op_status_, stmid_op_status_;
  std::string serialised_tmid_packet_, serialised_stmid_packet_, public_name_;
  const boost::uint8_t kMaxStoreAttempts_, kMaxDeleteAttempts_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_AUTHENTICATION_H_
