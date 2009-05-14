/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  RPCs used by vault
* Version:      1.0
* Created:      2009-02-22-00.18.57
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

#ifndef MAIDSAFE_VAULT_VAULTRPC_H_
#define MAIDSAFE_VAULT_VAULTRPC_H_

#include <string>

#include "base/utils.h"
#include "protobuf/maidsafe_service.pb.h"
#include "rpcprotocol/channel.h"
#include "rpcprotocol/channelmanager.h"

namespace maidsafe_vault {

class VaultRpcs {
 public:
  explicit VaultRpcs(rpcprotocol::ChannelManager *channel_manager);
  ~VaultRpcs() {}
  void StoreChunk(const std::string &chunkname,
             const std::string &data,
             const std::string &public_key,
             const std::string &signed_public_key,
             const std::string &signed_request,
             const maidsafe::value_types &data_type,
             const std::string &remote_ip,
             const uint16_t &remote_port,
             maidsafe::StoreResponse* response,
             google::protobuf::Closure* done,
             const bool &local);
  void CheckChunk(const std::string &chunkname,
                  const std::string &remote_ip,
                  const uint16_t &remote_port,
                  maidsafe::CheckChunkResponse* response,
                  google::protobuf::Closure* done,
                  const bool &local);
  void Get(const std::string &chunkname,
           const std::string &remote_ip,
           const uint16_t &remote_port,
           maidsafe::GetResponse* response,
           google::protobuf::Closure* done,
           const bool &local);
  void Update(const std::string &chunkname,
              const std::string &data,
              const std::string &public_key,
              const std::string &signed_public_key,
              const std::string &signed_request,
              const maidsafe::value_types &data_type,
              const std::string &remote_ip,
              const uint16_t &remote_port,
              maidsafe::UpdateResponse* response,
              google::protobuf::Closure* done,
              const bool &local);
  void Delete(const std::string &chunkname,
              const std::string &public_key,
              const std::string &signed_public_key,
              const std::string &signed_request,
              const maidsafe::value_types &data_type,
              const std::string &remote_ip,
              const uint16_t &remote_port,
              maidsafe::DeleteResponse* response,
              google::protobuf::Closure* done,
              const bool &local);
  void ValidityCheck(const std::string &chunkname,
                     const std::string &random_data,
                     const std::string &remote_ip,
                     const uint16_t &remote_port,
                     maidsafe::ValidityCheckResponse* response,
                     google::protobuf::Closure* done,
                     const bool &local);
  void GetMessages(const std::string &buffer_packet_name,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const std::string &remote_ip,
                   const uint16_t &remote_port,
                   maidsafe::GetMessagesResponse* response,
                   google::protobuf::Closure* done,
                   const bool &local);
  void SwapChunk(const boost::uint32_t request_type,
                 const std::string &chunkname1,
                 const std::string &chunkcontent1,
                 const boost::uint32_t size1,
                 const std::string &remote_ip,
                 const uint16_t &remote_port,
                 maidsafe::SwapChunkResponse* response,
                 google::protobuf::Closure* done,
                 const bool &local);
 private:
  VaultRpcs(const VaultRpcs&);
  VaultRpcs& operator=(const VaultRpcs&);
  rpcprotocol::ChannelManager *channel_manager_;
};
}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTRPC_H_
