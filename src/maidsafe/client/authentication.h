/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Creates, stores and accesses user details
* Version:      1.0
* Created:      2009-01-28-22.18.47
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include <list>
#include <string>

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/client/systempackets.h"

namespace maidsafe {

class AuthCallbackResult {
 public:
  AuthCallbackResult();
  void CallbackFunc(const std::string &res);
  void Reset();
  std::string result;
};

class Authentication {
 public:
  Authentication();
  void Init(boost::shared_ptr<StoreManagerInterface> smgr);
  int GetUserInfo(const std::string &username, const std::string &pin);
  int GetUserData(const std::string &password, std::string &ser_da);
  int CreateUserSysPackets(const std::string &username, const std::string &pin,
                           uint32_t *rid);
  int CreateTmidPacket(const std::string &username, const std::string &pin,
    const std::string &password, const uint32_t& rid,
    const std::string &ser_dm);
  int SaveSession(std::string ser_da,
                  PacketParams priv_keys,
                  PacketParams pub_keys);
  int RemoveMe(std::list<KeyAtlasRow> sig_keys);
  int CreatePublicName(std::string public_username, PacketParams *result);
  int ChangeUsername(std::string ser_da,
                     PacketParams priv_keys,
                     PacketParams pub_keys,
                     std::string new_username);
  int ChangePin(std::string ser_da,
                PacketParams priv_keys,
                PacketParams pub_keys,
                std::string new_pin);
  int ChangePassword(std::string ser_da,
                     PacketParams priv_keys,
                     PacketParams pub_keys,
                     std::string new_password);
  bool CheckUserExists(std::string username, std::string pin);
  int PublicUsernamePublicKey(const std::string &public_username,
                              std::string &public_key);
  void CreateMSIDPacket(base::callback_func_type cb);
 private:
  std::string createSignaturePackets(const PacketType &type_da,
                                     std::string &public_key);
  bool CheckUsername(const std::string &username);
  bool CheckPin(const std::string &pin);
  bool CheckPassword(const std::string &password);
  int CreateSignedRequest(const std::string &private_key,
                          const std::string &public_key,
                          const std::string &hex_packet_name,
                          std::string *signed_public_key,
                          std::string *signed_request);
  bool GetMid(const std::string &username, const std::string &pin, int *rid);
  bool GetSmid(const std::string &smid_name,
               const std::string &pin,
               int *rid);
  void WaitForResult(const AuthCallbackResult &cb);
  void GetUserTmid(bool smid);

  UserDetails ud_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;
  boost::shared_ptr<StoreManagerInterface> storemanager_;
  SessionSingleton *ss_;
  std::string tmid_content_;
  Authentication &operator=(const Authentication &);
  Authentication(const Authentication &);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_AUTHENTICATION_H_
