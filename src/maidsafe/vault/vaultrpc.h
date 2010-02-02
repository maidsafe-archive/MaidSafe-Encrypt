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

#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>
#include <string>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe_vault {

class VaultRpcs {
 public:
  VaultRpcs(transport::Transport *transport,
            rpcprotocol::ChannelManager *channel_manager)
                : transport_(transport),
                  channel_manager_(channel_manager),
                  own_non_hex_id_("") {}
  virtual ~VaultRpcs() {}
  void StoreChunk(const std::string &chunkname,
                  const std::string &data,
                  const std::string &public_key,
                  const std::string &public_key_signature,
                  const std::string &request_signature,
                  const maidsafe::ValueType &data_type,
                  const std::string &remote_ip,
                  const boost::uint16_t &remote_port,
                  const std::string &rendezvous_ip,
                  const boost::uint16_t &rendezvous_port,
                  maidsafe::StoreChunkResponse *response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  virtual void AddToReferenceList(
      const kad::Contact &peer,
      bool local,
      maidsafe::AddToReferenceListRequest *add_to_reference_list_request,
      maidsafe::AddToReferenceListResponse *add_to_reference_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  void RemoveFromReferenceList(
      const kad::Contact &peer,
      bool local,
      maidsafe::RemoveFromReferenceListRequest
          *remove_from_reference_list_request,
      maidsafe::RemoveFromReferenceListResponse
          *remove_from_reference_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  virtual void AmendAccount(
      const kad::Contact &peer,
      bool local,
      maidsafe::AmendAccountRequest *amend_account_request,
      maidsafe::AmendAccountResponse *amend_account_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  virtual void AccountStatus(
      const kad::Contact &peer,
      bool local,
      maidsafe::AccountStatusRequest *get_account_status_request,
      maidsafe::AccountStatusResponse *get_account_status_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  void CheckChunk(const std::string &chunkname,
                  const std::string &remote_ip,
                  const boost::uint16_t &remote_port,
                  const std::string &rendezvous_ip,
                  const boost::uint16_t &rendezvous_port,
                  maidsafe::CheckChunkResponse *response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  void GetChunk(const std::string &chunkname,
                const std::string &remote_ip,
                const boost::uint16_t &remote_port,
                const std::string &rendezvous_ip,
                const boost::uint16_t &rendezvous_port,
                maidsafe::GetChunkResponse *response,
                rpcprotocol::Controller *controller,
                google::protobuf::Closure *done);
  void DeleteChunk(const std::string &chunkname,
               const std::string &public_key,
               const std::string &public_key_signature,
               const std::string &request_signature,
               const maidsafe::ValueType &data_type,
               const std::string &remote_ip,
               const boost::uint16_t &remote_port,
               const std::string &rendezvous_ip,
               const boost::uint16_t &rendezvous_port,
               maidsafe::DeleteChunkResponse *response,
               rpcprotocol::Controller *controller,
               google::protobuf::Closure *done);
  void ValidityCheck(const std::string &chunkname,
                     const std::string &random_data,
                     const std::string &remote_ip,
                     const boost::uint16_t &remote_port,
                     const std::string &rendezvous_ip,
                     const boost::uint16_t &rendezvous_port,
                     maidsafe::ValidityCheckResponse *response,
                     rpcprotocol::Controller *controller,
                     google::protobuf::Closure *done);
  void SwapChunk(const boost::uint32_t request_type,
                 const std::string &chunkname1,
                 const std::string &chunkcontent1,
                 const boost::uint32_t size1,
                 const std::string &remote_ip,
                 const boost::uint16_t &remote_port,
                 const std::string &rendezvous_ip,
                 const boost::uint16_t &rendezvous_port,
                 maidsafe::SwapChunkResponse *response,
                 rpcprotocol::Controller *controller,
                 google::protobuf::Closure *done);
  void GetBPMessages(const std::string &buffer_packet_name,
                     const std::string &public_key,
                     const std::string &public_key_signature,
                     const std::string &remote_ip,
                     const boost::uint16_t &remote_port,
                     const std::string &rendezvous_ip,
                     const boost::uint16_t &rendezvous_port,
                     maidsafe::GetBPMessagesResponse *response,
                     rpcprotocol::Controller *controller,
                     google::protobuf::Closure *done);
  virtual void CacheChunk(const std::string &remote_ip,
                          const boost::uint16_t &remote_port,
                          const std::string &rendezvous_ip,
                          const boost::uint16_t &rendezvous_port,
                          maidsafe::CacheChunkRequest *request,
                          maidsafe::CacheChunkResponse *response,
                          rpcprotocol::Controller *controller,
                          google::protobuf::Closure *done);
  void SetOwnId(const std::string &non_hex_id) { own_non_hex_id_ = non_hex_id; }
 private:
  VaultRpcs(const VaultRpcs&);
  VaultRpcs& operator=(const VaultRpcs&);
  transport::Transport *transport_;
  rpcprotocol::ChannelManager *channel_manager_;
  std::string own_non_hex_id_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTRPC_H_
