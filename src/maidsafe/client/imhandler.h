/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class that Validates and creates messages for im
* Version:      1.0
* Created:      2010-04-13
* Revision:     none
* Compiler:     gcc
* Author:
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

#ifndef MAIDSAFE_CLIENT_IMHANDLER_H_
#define MAIDSAFE_CLIENT_IMHANDLER_H_

#include <maidsafe/base/crypto.h>
#include <string>
#include "protobuf/packet.pb.h"

namespace maidsafe {

class SessionSingleton;
namespace test {
class CCImMessagingTest;
}  // namespace test

class IMHandler {
 public:
  explicit IMHandler(SessionSingleton *ss);
  std::string CreateMessage(const std::string &msg,
                            const std::string &receiver);
  bool ValidateMessage(const std::string &ser_msg, MessageType *type,
                       std::string *validated_msg);
  std::string CreateMessageEndpoint(const std::string &receiver);
  std::string CreateLogOutMessage(const std::string &receiver);
 private:
  friend class test::CCImMessagingTest;
  SessionSingleton *ss_;
  crypto::Crypto crypto_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_IMHANDLER_H_
