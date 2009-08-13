/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages buffer packet messages to the maidsafe vault
* Version:      1.0
* Created:      2009-01-29-00.59.23
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

#ifndef MAIDSAFE_VAULT_VAULTBUFFERPACKETHANDLER_H_
#define MAIDSAFE_VAULT_VAULTBUFFERPACKETHANDLER_H_

#include <maidsafe/crypto.h>
#include <maidsafe/utils.h>
#include <list>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"

namespace packethandler {

class VaultBufferPacketHandler {
 public:
  VaultBufferPacketHandler();
  bool ValidateOwnerSignature(std::string public_key,
                              std::string ser_bufferpacket);
  bool CheckStatus(const std::string &current_bp,
                    const std::string &ser_message,
                    const std::string &signed_public_key,
                    int *status);
  bool GetMessages(const std::string &ser_bp, std::vector<std::string> *msgs);
  bool ClearMessages(std::string *ser_bufferpacket);
  bool IsOwner(std::string owner_id, GenericPacket gp_info);
  bool ChangeOwnerInfo(std::string ser_gp,
                       std::string *ser_packet,
                       std::string public_key);
  bool AddMessage(const std::string &current_bp,
                    const std::string &ser_message,
                    const std::string &signed_public_key,
                    std::string *updated_bp);


  bool CheckMsgStructure(const std::string &ser_message,
                         std::string &sender_id,
                         MessageType &type);

 private:
  crypto::Crypto crypto_obj_;
  VaultBufferPacketHandler &operator=(const VaultBufferPacketHandler);
  VaultBufferPacketHandler(const VaultBufferPacketHandler&);
};

}  // namespace packethandler

#endif  // MAIDSAFE_VAULT_VAULTBUFFERPACKETHANDLER_H_
