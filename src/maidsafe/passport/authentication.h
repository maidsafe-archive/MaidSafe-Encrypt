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

#ifndef MAIDSAFE_PASSPORT_AUTHENTICATION_H_
#define MAIDSAFE_PASSPORT_AUTHENTICATION_H_

#include <list>
#include <string>
#include <vector>

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/common/cryptokeypairs.h"
#include "maidsafe/common/returncodes.h"
#include "maidsafe/passport/systempackets.h"

namespace maidsafe {

typedef boost::function<void(const maidsafe::ReturnCode&)> VoidFuncOneInt;

struct SystemPacketCreation {
  SystemPacketCreation() : vfoi(), packet_count(0), username(), pin(), rid(0) {}
  VoidFuncOneInt vfoi;
  int packet_count;
  std::string username, pin;
  boost::uint32_t rid;
};

struct FindSystemPacket {
  FindSystemPacket() : spc(), pp(), pt() {}
  boost::shared_ptr<SystemPacketCreation> spc;
  PacketParams pp;
  PacketType pt;
};

struct UserInfo {
  UserInfo() : m(), mid_calledback(false), smid_calledback(false),
               tmid_mid_calledback(false), tmid_smid_calledback(false), func(),
               username(), pin() { }
  boost::mutex m;
  bool mid_calledback;
  bool smid_calledback;
  bool tmid_mid_calledback;
  bool tmid_smid_calledback;
  VoidFuncOneInt func;
  std::string username;
  std::string pin;
};

struct SaveSessionData {
  std::string ser_da;
  std::string current_encripted_mid;
  std::string mid_tmid_data;
  boost::uint32_t new_mid;
  VoidFuncOneInt vfoi;
  bool same_mid_smid;
};

class Authentication {
 public:
  Authentication()
      : ud_(),
        mutex_(),
        crypto_(),
        sm_(),
        ss_(),
        system_packets_result_(kPendingResult),
        user_info_result_(kPendingResult),
        get_smidtimid_result_(kPendingResult),
        crypto_key_pairs_() { }
  ~Authentication() { }
  void Init(const boost::uint16_t &crypto_key_buffer_count,
            boost::shared_ptr<StoreManagerInterface> smgr);
//  void Init(const boost::uint16_t &crypto_key_buffer_count,
//            boost::shared_ptr<StoreManagerInterface> smgr,
//            SessionSingleton *ss);
  int GetUserInfo(const std::string &username, const std::string &pin);
  int GetUserData(const std::string &password, std::string *ser_da);
  int CreateUserSysPackets(const std::string &username,
                           const std::string &pin);
  void CreateUserSysPackets(const ReturnCode &rc,
                            const std::string &username,
                            const std::string &pin,
                            VoidFuncOneInt vfoi,
                            boost::uint16_t *count,
                            bool *calledback);
  int CreateTmidPacket(const std::string &username,
                       const std::string &pin,
                       const std::string &password,
                       const std::string &ser_dm);
  int SaveSession(const std::string &ser_da);
  void SaveSession(const std::string &ser_da, const VoidFuncOneInt &cb);
  int RemoveMe(std::list<KeyAtlasRow> sig_keys);
  int CreatePublicName(const std::string &public_username);
  int ChangeUsername(const std::string &ser_da,
                     const std::string &new_username);
  int ChangePin(const std::string &ser_da,
                const std::string &new_pin);
  int ChangePassword(const std::string &ser_da,
                     const std::string &new_password);
  int PublicUsernamePublicKey(const std::string &public_username,
                              std::string *public_key);
  void CreateMSIDPacket(kad::VoidFunctorOneString cb);
  ReturnCode get_smidtimid_result() {
    return get_smidtimid_result_;
  }
 private:
  std::string CreateSignaturePackets(const PacketType &type_da,
                                     std::string *public_key);
  void CreateSignaturePacket(boost::shared_ptr<SystemPacketCreation> spc,
                             const PacketType &type_da);
  bool CheckUsername(const std::string &username);
  bool CheckPin(const std::string &pin);
  bool CheckPassword(const std::string &password);

  void GetMidCallback(const std::vector<std::string> &values,
                      const ReturnCode &rc,
                      boost::shared_ptr<UserInfo> ui);
  void GetSmidCallback(const std::vector<std::string> &values,
                       const ReturnCode &rc,
                       boost::shared_ptr<UserInfo> ui);
  void GetMidTmid(boost::shared_ptr<UserInfo> ui);
  void GetSmidTmid(boost::shared_ptr<UserInfo> ui);
  void GetMidTmidCallback(const std::vector<std::string> &values,
                          const ReturnCode &rc,
                          boost::shared_ptr<UserInfo> ui);
  void GetSmidTmidCallback(const std::vector<std::string> &values,
                           const ReturnCode &rc,
                           boost::shared_ptr<UserInfo> ui);

  int StorePacket(const std::string &packet_name,
                  const std::string &value,
                  const PacketType &type,
                  const std::string &msid);
  // Unneccessary, but more efficient/faster to pass packet's value here
  int DeletePacket(const std::string &packet_name,
                   const std::string &value,
                   const PacketType &type);
  void PacketOpCallback(const int &store_manager_result,
                        boost::mutex *mutex,
                        boost::condition_variable *cond_var,
                        int *op_result);
  void CreateSignaturePacketKeyUnique(const ReturnCode &rc,
                                      boost::shared_ptr<FindSystemPacket> fsp);
  void CreateSignaturePacketStore(const ReturnCode &rc,
                                  boost::shared_ptr<FindSystemPacket> fsp);
  void CreateSystemPacketsCallback(const ReturnCode &rc);
  void GetUserInfoCallback(const ReturnCode &rc);
  void CreateMidPacket(boost::shared_ptr<FindSystemPacket> fsp);
  void CreateSmidPacket(boost::shared_ptr<FindSystemPacket> fsp);
  void CreateMaidPmidPacket(boost::shared_ptr<FindSystemPacket> fsp);
  std::string EncryptedDataMidSmid(boost::uint32_t rid);

  void UpdateSmidCallback(const ReturnCode &rc,
                          boost::shared_ptr<SaveSessionData> ssd);
  void DeleteSmidTmidCallback(const ReturnCode &rc,
                              boost::shared_ptr<SaveSessionData> ssd);
  void UpdateMidCallback(const ReturnCode &rc,
                         boost::shared_ptr<SaveSessionData> ssd);
  void StoreMidTmidCallback(const ReturnCode &rc,
                            boost::shared_ptr<SaveSessionData> ssd);
  void SaveSessionCallback(const ReturnCode &rc,
                           ReturnCode *return_code_out,
                           boost::condition_variable *cond_var,
                           boost::mutex *mutex);

  UserDetails ud_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;
  boost::shared_ptr<StoreManagerInterface> sm_;
  SessionSingleton *ss_;
  ReturnCode system_packets_result_, user_info_result_, get_smidtimid_result_;
  CryptoKeyPairs crypto_key_pairs_;
  Authentication &operator=(const Authentication &);
  Authentication(const Authentication &);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_AUTHENTICATION_H_
