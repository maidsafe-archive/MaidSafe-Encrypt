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

namespace ph = packethandler;

namespace maidsafe {

enum exitcode {
  OK,
  FAIL,
  PASSWORD_FAIL,
  NON_EXISTING_USER,
  USER_EXISTS,
  NO_CONNECTION,
  INVALID_USERNAME,
  INVALID_PIN,
  INVALID_PASSWORD,
  PUBLIC_USERNAME_EXISTS,
  INVALID_USERNAME_PIN
};

class AuthCallbackResult {
 public:
  AuthCallbackResult();
  void CallbackFunc(const std::string &res);
  void Reset();
  std::string result;
};

class Authentication {
 public:
  Authentication(StoreManagerInterface *storemanager,
                 boost::recursive_mutex *mutex);
  exitcode GetUserInfo(const std::string &username,
                      const std::string &pin,
                      base::callback_func_type cb);
  exitcode GetUserData(const std::string &password, std::string &ser_da);
  exitcode CreateUserSysPackets(const std::string &username,
                                const std::string &pin,
                                const std::string &password);
  exitcode SaveSession(std::string ser_da,
                       ph::PacketParams priv_keys,
                       ph::PacketParams pub_keys);
  exitcode RemoveMe(std::list<KeyAtlasRow> sig_keys);
  exitcode CreatePublicName(std::string public_username,
                            ph::PacketParams *result);
  exitcode ChangeUsername(std::string ser_da,
                          ph::PacketParams priv_keys,
                          ph::PacketParams pub_keys,
                          std::string new_username);
  exitcode ChangePin(std::string ser_da,
                     ph::PacketParams priv_keys,
                     ph::PacketParams pub_keys,
                     std::string new_pin);
  exitcode ChangePassword(std::string ser_da,
                          ph::PacketParams priv_keys,
                          ph::PacketParams pub_keys,
                          std::string new_password);
  bool CheckUserExists(std::string username, std::string pin);
  exitcode PublicUsernamePublicKey(const std::string &public_username,
                                   std::string &public_key);
  void CreateMSIDPacket(base::callback_func_type cb);
 private:
  std::string createSignaturePackets(const packethandler::SystemPackets &type,
                                     const PacketType &type_da,
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
  void GetUserTmid(base::callback_func_type cb, bool smid);
  void GetUserTmidCallback(const std::string &result,
                           bool smid,
                           base::callback_func_type cb);
  void CheckMSIDUnique_Callback(const std::string &result, int retry,
                                ph::PacketParams params,
                                base::callback_func_type cb);
  void StoreMSID_Callback(const std::string &result,
                          ph::PacketParams params,
                          base::callback_func_type cb);
  UserDetails ud_;
  boost::recursive_mutex *mutex_;
  maidsafe_crypto::Crypto crypto_;
  StoreManagerInterface *storemanager_;
  SessionSingleton *ss_;
  std::string tmid_content;
  Authentication &operator=(const Authentication &) { return *this; }
  Authentication(const Authentication &);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_AUTHENTICATION_H_
