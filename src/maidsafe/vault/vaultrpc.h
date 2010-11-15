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
#include <string>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/maidsafe_service.pb.h"

namespace maidsafe {

namespace vault {

class VaultRpcs {
 public:
  VaultRpcs(transport::TransportHandler *transport_handler,
            rpcprotocol::ChannelManager *channel_manager)
                : transport_handler_(transport_handler),
                  channel_manager_(channel_manager),
                  own_id_() {}
  virtual ~VaultRpcs() {}
  void StoreChunk(const std::string &chunkname,
                  const std::string &data,
                  const std::string &public_key,
                  const std::string &public_key_signature,
                  const std::string &request_signature,
                  const ValueType &data_type,
                  const std::string &remote_ip,
                  const boost::uint16_t &remote_port,
                  const std::string &rendezvous_ip,
                  const boost::uint16_t &rendezvous_port,
                  const boost::int16_t &transport_id,
                  StoreChunkResponse *response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  virtual void AddToReferenceList(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      AddToReferenceListRequest *add_to_reference_list_request,
      AddToReferenceListResponse *add_to_reference_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  void GetChunkReferences(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      GetChunkReferencesRequest *get_chunk_references_request,
      GetChunkReferencesResponse *get_chunk_references_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  virtual void AmendAccount(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      AmendAccountRequest *amend_account_request,
      AmendAccountResponse *amend_account_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  virtual void ExpectAmendment(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      ExpectAmendmentRequest *expect_amendment_request,
      ExpectAmendmentResponse *expect_amendment_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  virtual void AccountStatus(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      AccountStatusRequest *get_account_status_request,
      AccountStatusResponse *get_account_status_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  void CheckChunk(const std::string &chunkname,
                  const std::string &remote_ip,
                  const boost::uint16_t &remote_port,
                  const std::string &rendezvous_ip,
                  const boost::uint16_t &rendezvous_port,
                  const boost::int16_t &transport_id,
                  CheckChunkResponse *response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  void GetChunk(const std::string &chunkname,
                const std::string &remote_ip,
                const boost::uint16_t &remote_port,
                const std::string &rendezvous_ip,
                const boost::uint16_t &rendezvous_port,
                const boost::int16_t &transport_id,
                GetChunkResponse *response,
                rpcprotocol::Controller *controller,
                google::protobuf::Closure *done);
  void DeleteChunk(const std::string &chunkname,
               const std::string &public_key,
               const std::string &public_key_signature,
               const std::string &request_signature,
               const ValueType &data_type,
               const std::string &remote_ip,
               const boost::uint16_t &remote_port,
               const std::string &rendezvous_ip,
               const boost::uint16_t &rendezvous_port,
               const boost::int16_t &transport_id,
               DeleteChunkResponse *response,
               rpcprotocol::Controller *controller,
               google::protobuf::Closure *done);
  void ValidityCheck(const std::string &chunkname,
                     const std::string &random_data,
                     const std::string &remote_ip,
                     const boost::uint16_t &remote_port,
                     const std::string &rendezvous_ip,
                     const boost::uint16_t &rendezvous_port,
                     const boost::int16_t &transport_id,
                     ValidityCheckResponse *response,
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
                 const boost::int16_t &transport_id,
                 SwapChunkResponse *response,
                 rpcprotocol::Controller *controller,
                 google::protobuf::Closure *done);
  virtual void CacheChunk(const std::string &remote_ip,
                          const boost::uint16_t &remote_port,
                          const std::string &rendezvous_ip,
                          const boost::uint16_t &rendezvous_port,
                          const boost::int16_t &transport_id,
                          CacheChunkRequest *request,
                          CacheChunkResponse *response,
                          rpcprotocol::Controller *controller,
                          google::protobuf::Closure *done);
  void GetSyncData(const kad::Contact &peer,
                   bool local,
                   const boost::int16_t &transport_id,
                   GetSyncDataRequest *get_sync_data_request,
                   GetSyncDataResponse *get_sync_data_response,
                   rpcprotocol::Controller *controller,
                   google::protobuf::Closure *done);
  void GetAccount(const kad::Contact &peer,
                  bool local,
                  const boost::int16_t &transport_id,
                  GetAccountRequest *get_account_request,
                  GetAccountResponse *get_account_response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  void GetChunkInfo(const kad::Contact &peer,
                    bool local,
                    const boost::int16_t &transport_id,
                    GetChunkInfoRequest *get_chunk_info_request,
                    GetChunkInfoResponse *get_chunk_info_response,
                    rpcprotocol::Controller *controller,
                    google::protobuf::Closure *done);
  void GetBufferPacket(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      GetBufferPacketRequest *get_buffer_packet_request,
      GetBufferPacketResponse *get_buffer_packet_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  void GetBPMessages(const std::string &buffer_packet_name,
                     const std::string &public_key,
                     const std::string &public_key_signature,
                     const std::string &remote_ip,
                     const boost::uint16_t &remote_port,
                     const std::string &rendezvous_ip,
                     const boost::uint16_t &rendezvous_port,
                     const boost::int16_t &transport_id,
                     GetBPMessagesResponse *response,
                     rpcprotocol::Controller *controller,
                     google::protobuf::Closure *done);
  void SetOwnId(const std::string &id) { own_id_ = id; }
 private:
  VaultRpcs(const VaultRpcs&);
  VaultRpcs& operator=(const VaultRpcs&);
  transport::TransportHandler *transport_handler_;
  rpcprotocol::ChannelManager *channel_manager_;
  std::string own_id_;
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_VAULTRPC_H_
