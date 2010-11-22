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

#include <string>
#include "maidsafe/common/packet.pb.h"

namespace maidsafe {

class SessionSingleton;
namespace test {
class CCImMessagingTest;
class MultiImHandlerTest;
class ImMessagingTest_FUNC_MAID_SendReceiveMessages_Test;
class ImMessagingTest_FUNC_MAID_ReceiveEndPointMsg_Test;
class ImMessagingTest_FUNC_MAID_ReceiveLogOutMsg_Test;
class ImMessagingTest_FUNC_MAID_HandleTwoConverstions_Test;
class ImMessagingTest_FUNC_MAID_NET_SendReceiveMessages_Test;
class ImMessagingTest_FUNC_MAID_NET_ReceiveEndPointMsg_Test;
class ImMessagingTest_FUNC_MAID_NET_ReceiveLogOutMsg_Test;
class ImMessagingTest_FUNC_MAID_NET_HandleTwoConverstions_Test;
}  // namespace test

class IMHandler {
 public:
  explicit IMHandler();
  std::string CreateMessage(const std::string &msg,
                            const std::string &receiver);
  bool ValidateMessage(const std::string &ser_msg, MessageType *type,
                       std::string *validated_msg);
  std::string CreateMessageEndpoint(const std::string &receiver);
  std::string CreateLogOutMessage(const std::string &receiver);
 private:
  friend class test::CCImMessagingTest;
  friend class test::MultiImHandlerTest;
  friend class test::ImMessagingTest_FUNC_MAID_SendReceiveMessages_Test;
  friend class test::ImMessagingTest_FUNC_MAID_ReceiveEndPointMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_ReceiveLogOutMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_HandleTwoConverstions_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_SendReceiveMessages_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_ReceiveEndPointMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_ReceiveLogOutMsg_Test;
  friend class test::ImMessagingTest_FUNC_MAID_NET_HandleTwoConverstions_Test;
  SessionSingleton *ss_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_IMHANDLER_H_
