/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class for processing RPC messages.
* Created:      2011-01-17
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

#ifndef MAIDSAFE_COMMON_MESSAGEHANDLER_H_
#define MAIDSAFE_COMMON_MESSAGEHANDLER_H_

#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>
#include <maidsafe/kademlia/messagehandler.h>

#include <string>

namespace bs2 = boost::signals2;

namespace maidsafe {

namespace protobuf {
class StorePrepRequest;
class StorePrepResponse;
class StoreChunkRequest;
class StoreChunkResponse;
class GetChunkRequest;
class GetChunkResponse;
class HasChunkRequest;
class HasChunkResponse;
class GetChunkReferencesRequest;
class GetChunkReferencesResponse;
class AddToWatchListRequest;
class AddToWatchListResponse;
class RemoveFromWatchListRequest;
class RemoveFromWatchListResponse;
class AddToReferenceListRequest;
class AddToReferenceListResponse;
class AmendAccountRequest;
class AmendAccountResponse;
class ExpectAmendmentRequest;
class ExpectAmendmentResponse;
class AccountStatusRequest;
class AccountStatusResponse;
class GetSyncDataRequest;
class GetSyncDataResponse;
class GetAccountRequest;
class GetAccountResponse;
class GetChunkInfoRequest;
class GetChunkInfoResponse;
class GetBufferRequest;
class GetBufferResponse;
class CreateBufferRequest;
class CreateBufferResponse;
class ModifyBufferInfoRequest;
class ModifyBufferInfoResponse;
class GetBufferMessagesRequest;
class GetBufferMessagesResponse;
class AddBufferMessageRequest;
class AddBufferMessageResponse;
class GetBufferPresenceRequest;
class GetBufferPresenceResponse;
class AddBufferPresenceRequest;
class AddBufferPresenceResponse;
}  // namespace protobuf

// Highest possible message type ID, use as offset for type extensions.
const int kMaxMessageType(kademlia::kMaxMessageType);

class MessageHandler : public transport::MessageHandler {
 public:
  // StoreChunk signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::StoreChunkRequest&,
      protobuf::StoreChunkResponse*)> > StoreChunkReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::StoreChunkResponse&)> > StoreChunkRspSigPtr;
  // GetChunk signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetChunkRequest&,
      protobuf::GetChunkResponse*)> > GetChunkReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetChunkResponse&)> > GetChunkRspSigPtr;
  // HasChunk signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::HasChunkRequest&,
      protobuf::HasChunkResponse*)> > HasChunkReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::HasChunkResponse&)> > HasChunkRspSigPtr;
  // GetChunkReferences signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetChunkReferencesRequest&,
      protobuf::GetChunkReferencesResponse*)> > GetChunkReferencesReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetChunkReferencesResponse&)> >
      GetChunkReferencesRspSigPtr;
  // AddToWatchList signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::AddToWatchListRequest&,
      protobuf::AddToWatchListResponse*)> > AddToWatchListReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::AddToWatchListResponse&)> > AddToWatchListRspSigPtr;
  // RemoveFromWatchList signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::RemoveFromWatchListRequest&,
      protobuf::RemoveFromWatchListResponse*)> > RemoveFromWatchListReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::RemoveFromWatchListResponse&)> >
      RemoveFromWatchListRspSigPtr;
  // AddToReferenceList signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::AddToReferenceListRequest&,
      protobuf::AddToReferenceListResponse*)> > AddToReferenceListReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::AddToReferenceListResponse&)> >
      AddToReferenceListRspSigPtr;
  // AmendAccount signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::AmendAccountRequest&,
      protobuf::AmendAccountResponse*)> > AmendAccountReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::AmendAccountResponse&)> > AmendAccountRspSigPtr;
  // ExpectAmendment signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::ExpectAmendmentRequest&,
      protobuf::ExpectAmendmentResponse*)> > ExpectAmendmentReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::ExpectAmendmentResponse&)> > ExpectAmendmentRspSigPtr;
  // AccountStatus signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::AccountStatusRequest&,
      protobuf::AccountStatusResponse*)> > AccountStatusReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::AccountStatusResponse&)> > AccountStatusRspSigPtr;
  // GetSyncData signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetSyncDataRequest&,
      protobuf::GetSyncDataResponse*)> > GetSyncDataReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetSyncDataResponse&)> > GetSyncDataRspSigPtr;
  // GetAccount signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetAccountRequest&,
      protobuf::GetAccountResponse*)> > GetAccountReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetAccountResponse&)> > GetAccountRspSigPtr;
  // GetChunkInfo signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetChunkInfoRequest&,
      protobuf::GetChunkInfoResponse*)> > GetChunkInfoReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetChunkInfoResponse&)> > GetChunkInfoRspSigPtr;
  // GetBuffer signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetBufferRequest&,
      protobuf::GetBufferResponse*)> > GetBufferReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetBufferResponse&)> > GetBufferRspSigPtr;
  // CreateBuffer signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::CreateBufferRequest&,
      protobuf::CreateBufferResponse*)> > CreateBufferReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::CreateBufferResponse&)> > CreateBufferRspSigPtr;
  // ModifyBufferInfo signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::ModifyBufferInfoRequest&,
      protobuf::ModifyBufferInfoResponse*)> > ModifyBufferInfoReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::ModifyBufferInfoResponse&)> > ModifyBufferInfoRspSigPtr;
  // GetBufferMessages signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetBufferMessagesRequest&,
      protobuf::GetBufferMessagesResponse*)> > GetBufferMessagesReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetBufferMessagesResponse&)> > GetBufferMessagesRspSigPtr;
  // AddBufferMessage signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::AddBufferMessageRequest&,
      protobuf::AddBufferMessageResponse*)> > AddBufferMessageReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::AddBufferMessageResponse&)> > AddBufferMessageRspSigPtr;
  // GetBufferPresence signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::GetBufferPresenceRequest&,
      protobuf::GetBufferPresenceResponse*)> > GetBufferPresenceReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::GetBufferPresenceResponse&)> > GetBufferPresenceRspSigPtr;
  // AddBufferPresence signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::AddBufferPresenceRequest&,
      protobuf::AddBufferPresenceResponse*)> > AddBufferPresenceReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::AddBufferPresenceResponse&)> > AddBufferPresenceRspSigPtr;

  MessageHandler()
    : on_store_chunk_request_(new StoreChunkReqSigPtr::element_type),
      on_store_chunk_response_(new StoreChunkRspSigPtr::element_type),
      on_get_chunk_request_(new GetChunkReqSigPtr::element_type),
      on_get_chunk_response_(new GetChunkRspSigPtr::element_type),
      on_has_chunk_request_(new HasChunkReqSigPtr::element_type),
      on_has_chunk_response_(new HasChunkRspSigPtr::element_type),
      on_get_chunk_references_request_(
          new GetChunkReferencesReqSigPtr::element_type),
      on_get_chunk_references_response_(
          new GetChunkReferencesRspSigPtr::element_type),
      on_add_to_watch_list_request_(new AddToWatchListReqSigPtr::element_type),
      on_add_to_watch_list_response_(new AddToWatchListRspSigPtr::element_type),
      on_remove_from_watch_list_request_(
          new RemoveFromWatchListReqSigPtr::element_type),
      on_remove_from_watch_list_response_(
          new RemoveFromWatchListRspSigPtr::element_type),
      on_add_to_reference_list_request_(
          new AddToReferenceListReqSigPtr::element_type),
      on_add_to_reference_list_response_(
          new AddToReferenceListRspSigPtr::element_type),
      on_amend_account_request_(new AmendAccountReqSigPtr::element_type),
      on_amend_account_response_(new AmendAccountRspSigPtr::element_type),
      on_expect_amendment_request_(new ExpectAmendmentReqSigPtr::element_type),
      on_expect_amendment_response_(new ExpectAmendmentRspSigPtr::element_type),
      on_account_status_request_(new AccountStatusReqSigPtr::element_type),
      on_account_status_response_(new AccountStatusRspSigPtr::element_type),
      on_get_sync_data_request_(new GetSyncDataReqSigPtr::element_type),
      on_get_sync_data_response_(new GetSyncDataRspSigPtr::element_type),
      on_get_account_request_(new GetAccountReqSigPtr::element_type),
      on_get_account_response_(new GetAccountRspSigPtr::element_type),
      on_get_chunk_info_request_(new GetChunkInfoReqSigPtr::element_type),
      on_get_chunk_info_response_(new GetChunkInfoRspSigPtr::element_type),
      on_get_buffer_request_(new GetBufferReqSigPtr::element_type),
      on_get_buffer_response_(new GetBufferRspSigPtr::element_type),
      on_create_buffer_request_(new CreateBufferReqSigPtr::element_type),
      on_create_buffer_response_(new CreateBufferRspSigPtr::element_type),
      on_modify_buffer_info_request_(
          new ModifyBufferInfoReqSigPtr::element_type),
      on_modify_buffer_info_response_(
          new ModifyBufferInfoRspSigPtr::element_type),
      on_get_buffer_messages_request_(
          new GetBufferMessagesReqSigPtr::element_type),
      on_get_buffer_messages_response_(
          new GetBufferMessagesRspSigPtr::element_type),
      on_add_buffer_message_request_(
          new AddBufferMessageReqSigPtr::element_type),
      on_add_buffer_message_response_(
          new AddBufferMessageRspSigPtr::element_type),
      on_get_buffer_presence_request_(
          new GetBufferPresenceReqSigPtr::element_type),
      on_get_buffer_presence_response_(
          new GetBufferPresenceRspSigPtr::element_type),
      on_add_buffer_presence_request_(
          new AddBufferPresenceReqSigPtr::element_type),
      on_add_buffer_presence_response_(
          new AddBufferPresenceRspSigPtr::element_type) {}
  virtual ~MessageHandler() {}

  std::string WrapMessage(const protobuf::StoreChunkRequest &msg);
  std::string WrapMessage(const protobuf::StoreChunkResponse &msg);
  std::string WrapMessage(const protobuf::GetChunkRequest &msg);
  std::string WrapMessage(const protobuf::GetChunkResponse &msg);
  std::string WrapMessage(const protobuf::HasChunkRequest &msg);
  std::string WrapMessage(const protobuf::HasChunkResponse &msg);
  std::string WrapMessage(const protobuf::GetChunkReferencesRequest &msg);
  std::string WrapMessage(const protobuf::GetChunkReferencesResponse &msg);
  std::string WrapMessage(const protobuf::AddToWatchListRequest &msg);
  std::string WrapMessage(const protobuf::AddToWatchListResponse &msg);
  std::string WrapMessage(const protobuf::RemoveFromWatchListRequest &msg);
  std::string WrapMessage(const protobuf::RemoveFromWatchListResponse &msg);
  std::string WrapMessage(const protobuf::AddToReferenceListRequest &msg);
  std::string WrapMessage(const protobuf::AddToReferenceListResponse &msg);
  std::string WrapMessage(const protobuf::AmendAccountRequest &msg);
  std::string WrapMessage(const protobuf::AmendAccountResponse &msg);
  std::string WrapMessage(const protobuf::ExpectAmendmentRequest &msg);
  std::string WrapMessage(const protobuf::ExpectAmendmentResponse &msg);
  std::string WrapMessage(const protobuf::AccountStatusRequest &msg);
  std::string WrapMessage(const protobuf::AccountStatusResponse &msg);
  std::string WrapMessage(const protobuf::GetSyncDataRequest &msg);
  std::string WrapMessage(const protobuf::GetSyncDataResponse &msg);
  std::string WrapMessage(const protobuf::GetAccountRequest &msg);
  std::string WrapMessage(const protobuf::GetAccountResponse &msg);
  std::string WrapMessage(const protobuf::GetChunkInfoRequest &msg);
  std::string WrapMessage(const protobuf::GetChunkInfoResponse &msg);
  std::string WrapMessage(const protobuf::GetBufferRequest &msg);
  std::string WrapMessage(const protobuf::GetBufferResponse &msg);
  std::string WrapMessage(const protobuf::CreateBufferRequest &msg);
  std::string WrapMessage(const protobuf::CreateBufferResponse &msg);
  std::string WrapMessage(const protobuf::ModifyBufferInfoRequest &msg);
  std::string WrapMessage(const protobuf::ModifyBufferInfoResponse &msg);
  std::string WrapMessage(const protobuf::GetBufferMessagesRequest &msg);
  std::string WrapMessage(const protobuf::GetBufferMessagesResponse &msg);
  std::string WrapMessage(const protobuf::AddBufferMessageRequest &msg);
  std::string WrapMessage(const protobuf::AddBufferMessageResponse &msg);
  std::string WrapMessage(const protobuf::GetBufferPresenceRequest &msg);
  std::string WrapMessage(const protobuf::GetBufferPresenceResponse &msg);
  std::string WrapMessage(const protobuf::AddBufferPresenceRequest &msg);
  std::string WrapMessage(const protobuf::AddBufferPresenceResponse &msg);

  StoreChunkReqSigPtr on_store_chunk_request() {
    return on_store_chunk_request_;
  }
  StoreChunkRspSigPtr on_store_chunk_response() {
    return on_store_chunk_response_;
  }
  GetChunkReqSigPtr on_get_chunk_request() {
    return on_get_chunk_request_;
  }
  GetChunkRspSigPtr on_get_chunk_response() {
    return on_get_chunk_response_;
  }
  HasChunkReqSigPtr on_has_chunk_request() {
    return on_has_chunk_request_;
  }
  HasChunkRspSigPtr on_has_chunk_response() {
    return on_has_chunk_response_;
  }
  GetChunkReferencesReqSigPtr on_get_chunk_references_request() {
    return on_get_chunk_references_request_;
  }
  GetChunkReferencesRspSigPtr on_get_chunk_references_response() {
    return on_get_chunk_references_response_;
  }
  AddToWatchListReqSigPtr on_add_to_watch_list_request() {
    return on_add_to_watch_list_request_;
  }
  AddToWatchListRspSigPtr on_add_to_watch_list_response() {
    return on_add_to_watch_list_response_;
  }
  RemoveFromWatchListReqSigPtr on_remove_from_watch_list_request() {
    return on_remove_from_watch_list_request_;
  }
  RemoveFromWatchListRspSigPtr on_remove_from_watch_list_response() {
    return on_remove_from_watch_list_response_;
  }
  AddToReferenceListReqSigPtr on_add_to_reference_list_request() {
    return on_add_to_reference_list_request_;
  }
  AddToReferenceListRspSigPtr on_add_to_reference_list_response() {
    return on_add_to_reference_list_response_;
  }
  AmendAccountReqSigPtr on_amend_account_request() {
    return on_amend_account_request_;
  }
  AmendAccountRspSigPtr on_amend_account_response() {
    return on_amend_account_response_;
  }
  ExpectAmendmentReqSigPtr on_expect_amendment_request() {
    return on_expect_amendment_request_;
  }
  ExpectAmendmentRspSigPtr on_expect_amendment_response() {
    return on_expect_amendment_response_;
  }
  AccountStatusReqSigPtr on_account_status_request() {
    return on_account_status_request_;
  }
  AccountStatusRspSigPtr on_account_status_response() {
    return on_account_status_response_;
  }
  GetSyncDataReqSigPtr on_get_sync_data_request() {
    return on_get_sync_data_request_;
  }
  GetSyncDataRspSigPtr on_get_sync_data_response() {
    return on_get_sync_data_response_;
  }
  GetAccountReqSigPtr on_get_account_request() {
    return on_get_account_request_;
  }
  GetAccountRspSigPtr on_get_account_response() {
    return on_get_account_response_;
  }
  GetChunkInfoReqSigPtr on_get_chunk_info_request() {
    return on_get_chunk_info_request_;
  }
  GetChunkInfoRspSigPtr on_get_chunk_info_response() {
    return on_get_chunk_info_response_;
  }
  GetBufferReqSigPtr on_get_buffer_request() {
    return on_get_buffer_request_;
  }
  GetBufferRspSigPtr on_get_buffer_response() {
    return on_get_buffer_response_;
  }
  CreateBufferReqSigPtr on_create_buffer_request() {
    return on_create_buffer_request_;
  }
  CreateBufferRspSigPtr on_create_buffer_response() {
    return on_create_buffer_response_;
  }
  ModifyBufferInfoReqSigPtr on_modify_buffer_info_request() {
    return on_modify_buffer_info_request_;
  }
  ModifyBufferInfoRspSigPtr on_modify_buffer_info_response() {
    return on_modify_buffer_info_response_;
  }
  GetBufferMessagesReqSigPtr on_get_buffer_messages_request() {
    return on_get_buffer_messages_request_;
  }
  GetBufferMessagesRspSigPtr on_get_buffer_messages_response() {
    return on_get_buffer_messages_response_;
  }
  AddBufferMessageReqSigPtr on_add_buffer_message_request() {
    return on_add_buffer_message_request_;
  }
  AddBufferMessageRspSigPtr on_add_buffer_message_response() {
    return on_add_buffer_message_response_;
  }
  GetBufferPresenceReqSigPtr on_get_buffer_presence_request() {
    return on_get_buffer_presence_request_;
  }
  GetBufferPresenceRspSigPtr on_get_buffer_presence_response() {
    return on_get_buffer_presence_response_;
  }
  AddBufferPresenceReqSigPtr on_add_buffer_presence_request() {
    return on_add_buffer_presence_request_;
  }
  AddBufferPresenceRspSigPtr on_add_buffer_presence_response() {
    return on_add_buffer_presence_response_;
  }
 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const transport::Info &info,
                                        std::string *response,
                                        transport::Timeout *timeout);
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  StoreChunkReqSigPtr on_store_chunk_request_;
  StoreChunkRspSigPtr on_store_chunk_response_;
  GetChunkReqSigPtr on_get_chunk_request_;
  GetChunkRspSigPtr on_get_chunk_response_;
  HasChunkReqSigPtr on_has_chunk_request_;
  HasChunkRspSigPtr on_has_chunk_response_;
  GetChunkReferencesReqSigPtr on_get_chunk_references_request_;
  GetChunkReferencesRspSigPtr on_get_chunk_references_response_;
  AddToWatchListReqSigPtr on_add_to_watch_list_request_;
  AddToWatchListRspSigPtr on_add_to_watch_list_response_;
  RemoveFromWatchListReqSigPtr on_remove_from_watch_list_request_;
  RemoveFromWatchListRspSigPtr on_remove_from_watch_list_response_;
  AddToReferenceListReqSigPtr on_add_to_reference_list_request_;
  AddToReferenceListRspSigPtr on_add_to_reference_list_response_;
  AmendAccountReqSigPtr on_amend_account_request_;
  AmendAccountRspSigPtr on_amend_account_response_;
  ExpectAmendmentReqSigPtr on_expect_amendment_request_;
  ExpectAmendmentRspSigPtr on_expect_amendment_response_;
  AccountStatusReqSigPtr on_account_status_request_;
  AccountStatusRspSigPtr on_account_status_response_;
  GetSyncDataReqSigPtr on_get_sync_data_request_;
  GetSyncDataRspSigPtr on_get_sync_data_response_;
  GetAccountReqSigPtr on_get_account_request_;
  GetAccountRspSigPtr on_get_account_response_;
  GetChunkInfoReqSigPtr on_get_chunk_info_request_;
  GetChunkInfoRspSigPtr on_get_chunk_info_response_;
  GetBufferReqSigPtr on_get_buffer_request_;
  GetBufferRspSigPtr on_get_buffer_response_;
  CreateBufferReqSigPtr on_create_buffer_request_;
  CreateBufferRspSigPtr on_create_buffer_response_;
  ModifyBufferInfoReqSigPtr on_modify_buffer_info_request_;
  ModifyBufferInfoRspSigPtr on_modify_buffer_info_response_;
  GetBufferMessagesReqSigPtr on_get_buffer_messages_request_;
  GetBufferMessagesRspSigPtr on_get_buffer_messages_response_;
  AddBufferMessageReqSigPtr on_add_buffer_message_request_;
  AddBufferMessageRspSigPtr on_add_buffer_message_response_;
  GetBufferPresenceReqSigPtr on_get_buffer_presence_request_;
  GetBufferPresenceRspSigPtr on_get_buffer_presence_response_;
  AddBufferPresenceReqSigPtr on_add_buffer_presence_request_;
  AddBufferPresenceRspSigPtr on_add_buffer_presence_response_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_MESSAGEHANDLER_H_
