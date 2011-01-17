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

#include "maidsafe/common/messagehandler.h"
// #include "maidsafe/common/XXX.pb.h"

namespace kademlia {

enum MessageType {
  kStoreChunkRequest = kademlia::kMaxMessageType + 1,
  kStoreChunkResponse,
  kGetChunkRequest,
  kGetChunkResponse,
  kHasChunkRequest,
  kHasChunkResponse,
  kGetChunkReferencesRequest,
  kGetChunkReferencesResponse,
  kAddToWatchListRequest,
  kAddToWatchListResponse,
  kRemoveFromWatchListRequest,
  kRemoveFromWatchListResponse,
  kAddToReferenceListRequest,
  kAddToReferenceListResponse,
  kAmendAccountRequest,
  kAmendAccountResponse,
  kExpectAmendmentRequest,
  kExpectAmendmentResponse,
  kAccountStatusRequest,
  kAccountStatusResponse,
  kGetSyncDataRequest,
  kGetSyncDataResponse,
  kGetAccountRequest,
  kGetAccountResponse,
  kGetChunkInfoRequest,
  kGetChunkInfoResponse,
  kGetBufferRequest,
  kGetBufferResponse,
  kCreateBufferRequest,
  kCreateBufferResponse,
  kModifyBufferInfoRequest,
  kModifyBufferInfoResponse,
  kGetBufferMessagesRequest,
  kGetBufferMessagesResponse,
  kAddBufferMessageRequest,
  kAddBufferMessageResponse,
  kGetBufferPresenceRequest,
  kGetBufferPresenceResponse,
  kAddBufferPresenceRequest,
  kAddBufferPresenceResponse
};

std::string MessageHandler::WrapMessage(
    const protobuf::StoreChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kStoreChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::StoreChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kStoreChunkResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::GetChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::GetChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetChunkResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::HasChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kHasChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::HasChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kHasChunkResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetChunkReferencesRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetChunkReferencesRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetChunkReferencesResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetChunkReferencesResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddToWatchListRequest &msg) {
  return MakeSerialisedWrapperMessage(kAddToWatchListRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddToWatchListResponse &msg) {
  return MakeSerialisedWrapperMessage(kAddToWatchListResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::RemoveFromWatchListRequest &msg) {
  return MakeSerialisedWrapperMessage(kRemoveFromWatchListRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::RemoveFromWatchListResponse &msg) {
  return MakeSerialisedWrapperMessage(kRemoveFromWatchListResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddToReferenceListRequest &msg) {
  return MakeSerialisedWrapperMessage(kAddToReferenceListRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddToReferenceListResponse &msg) {
  return MakeSerialisedWrapperMessage(kAddToReferenceListResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AmendAccountRequest &msg) {
  return MakeSerialisedWrapperMessage(kAmendAccountRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AmendAccountResponse &msg) {
  return MakeSerialisedWrapperMessage(kAmendAccountResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ExpectAmendmentRequest &msg) {
  return MakeSerialisedWrapperMessage(kExpectAmendmentRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ExpectAmendmentResponse &msg) {
  return MakeSerialisedWrapperMessage(kExpectAmendmentResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AccountStatusRequest &msg) {
  return MakeSerialisedWrapperMessage(kAccountStatusRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AccountStatusResponse &msg) {
  return MakeSerialisedWrapperMessage(kAccountStatusResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetSyncDataRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetSyncDataRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetSyncDataResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetSyncDataResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetAccountRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetAccountRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetAccountResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetAccountResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetChunkInfoRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetChunkInfoRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetChunkInfoResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetChunkInfoResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::GetBufferRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetBufferRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetBufferResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetBufferResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::CreateBufferRequest &msg) {
  return MakeSerialisedWrapperMessage(kCreateBufferRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::CreateBufferResponse &msg) {
  return MakeSerialisedWrapperMessage(kCreateBufferResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ModifyBufferInfoRequest &msg) {
  return MakeSerialisedWrapperMessage(kModifyBufferInfoRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ModifyBufferInfoResponse &msg) {
  return MakeSerialisedWrapperMessage(kModifyBufferInfoResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetBufferMessagesRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetBufferMessagesRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetBufferMessagesResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetBufferMessagesResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddBufferMessageRequest &msg) {
  return MakeSerialisedWrapperMessage(kAddBufferMessageRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddBufferMessageResponse &msg) {
  return MakeSerialisedWrapperMessage(kAddBufferMessageResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetBufferPresenceRequest &msg) {
  return MakeSerialisedWrapperMessage(kGetBufferPresenceRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::GetBufferPresenceResponse &msg) {
  return MakeSerialisedWrapperMessage(kGetBufferPresenceResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddBufferPresenceRequest &msg) {
  return MakeSerialisedWrapperMessage(kAddBufferPresenceRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::AddBufferPresenceResponse &msg) {
  return MakeSerialisedWrapperMessage(kAddBufferPresenceResponse,
                                      msg.SerializeAsString());
}

void MessageHandler::ProcessSerialisedMessage(const int& message_type,
                                              const std::string& payload,
                                              const transport::Info& info,
                                              std::string* response,
                                              transport::Timeout* timeout) {
  response->clear();
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
    case kStoreChunkRequest: {
      protobuf::StoreChunkRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::StoreChunkResponse rsp;
        (*on_store_chunk_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kStoreChunkResponse: {
      protobuf::StoreChunkResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_store_chunk_response_)(req);
      break;
    }

    case kGetChunkRequest: {
      protobuf::GetChunkRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetChunkResponse rsp;
        (*on_get_chunk_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetChunkResponse: {
      protobuf::GetChunkResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_chunk_response_)(req);
      break;
    }

    case kHasChunkRequest: {
      protobuf::HasChunkRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::HasChunkResponse rsp;
        (*on_has_chunk_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kHasChunkResponse: {
      protobuf::HasChunkResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_has_chunk_response_)(req);
      break;
    }

    case kGetChunkReferencesRequest: {
      protobuf::GetChunkReferencesRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetChunkReferencesResponse rsp;
        (*on_get_chunk_references_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetChunkReferencesResponse: {
      protobuf::GetChunkReferencesResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_chunk_references_response_)(req);
      break;
    }

    case kAddToWatchListRequest: {
      protobuf::AddToWatchListRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::AddToWatchListResponse rsp;
        (*on_add_to_watch_list_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddToWatchListResponse: {
      protobuf::AddToWatchListResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_add_to_watch_list_response_)(req);
      break;
    }

    case kRemoveFromWatchListRequest: {
      protobuf::RemoveFromWatchListRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::RemoveFromWatchListResponse rsp;
        (*on_remove_from_watch_list_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kRemoveFromWatchListResponse: {
      protobuf::RemoveFromWatchListResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_remove_from_watch_list_response_)(req);
      break;
    }

    case kAddToReferenceListRequest: {
      protobuf::AddToReferenceListRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::AddToReferenceListResponse rsp;
        (*on_add_to_reference_list_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddToReferenceListResponse: {
      protobuf::AddToReferenceListResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_add_to_reference_list_response_)(req);
      break;
    }

    case kAmendAccountRequest: {
      protobuf::AmendAccountRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::AmendAccountResponse rsp;
        (*on_amend_account_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAmendAccountResponse: {
      protobuf::AmendAccountResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_amend_account_response_)(req);
      break;
    }

    case kExpectAmendmentRequest: {
      protobuf::ExpectAmendmentRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::ExpectAmendmentResponse rsp;
        (*on_expect_amendment_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kExpectAmendmentResponse: {
      protobuf::ExpectAmendmentResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_expect_amendment_response_)(req);
      break;
    }

    case kAccountStatusRequest: {
      protobuf::AccountStatusRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::AccountStatusResponse rsp;
        (*on_account_status_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAccountStatusResponse: {
      protobuf::AccountStatusResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_account_status_response_)(req);
      break;
    }

    case kGetSyncDataRequest: {
      protobuf::GetSyncDataRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetSyncDataResponse rsp;
        (*on_get_sync_data_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetSyncDataResponse: {
      protobuf::GetSyncDataResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_sync_data_response_)(req);
      break;
    }

    case kGetAccountRequest: {
      protobuf::GetAccountRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetAccountResponse rsp;
        (*on_get_account_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetAccountResponse: {
      protobuf::GetAccountResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_account_response_)(req);
      break;
    }

    case kGetChunkInfoRequest: {
      protobuf::GetChunkInfoRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetChunkInfoResponse rsp;
        (*on_get_chunk_info_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetChunkInfoResponse: {
      protobuf::GetChunkInfoResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_chunk_info_response_)(req);
      break;
    }

    case kGetBufferRequest: {
      protobuf::GetBufferRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetBufferResponse rsp;
        (*on_get_buffer_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetBufferResponse: {
      protobuf::GetBufferResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_buffer_response_)(req);
      break;
    }

    case kCreateBufferRequest: {
      protobuf::CreateBufferRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::CreateBufferResponse rsp;
        (*on_create_buffer_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kCreateBufferResponse: {
      protobuf::CreateBufferResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_create_buffer_response_)(req);
      break;
    }

    case kModifyBufferInfoRequest: {
      protobuf::ModifyBufferInfoRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::ModifyBufferInfoResponse rsp;
        (*on_modify_buffer_info_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kModifyBufferInfoResponse: {
      protobuf::ModifyBufferInfoResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_modify_buffer_info_response_)(req);
      break;
    }

    case kGetBufferMessagesRequest: {
      protobuf::GetBufferMessagesRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetBufferMessagesResponse rsp;
        (*on_get_buffer_messages_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetBufferMessagesResponse: {
      protobuf::GetBufferMessagesResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_buffer_messages_response_)(req);
      break;
    }

    case kAddBufferMessageRequest: {
      protobuf::AddBufferMessageRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::AddBufferMessageResponse rsp;
        (*on_add_buffer_message_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddBufferMessageResponse: {
      protobuf::AddBufferMessageResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_add_buffer_message_response_)(req);
      break;
    }

    case kGetBufferPresenceRequest: {
      protobuf::GetBufferPresenceRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::GetBufferPresenceResponse rsp;
        (*on_get_buffer_presence_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetBufferPresenceResponse: {
      protobuf::GetBufferPresenceResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_get_buffer_presence_response_)(req);
      break;
    }

    case kAddBufferPresenceRequest: {
      protobuf::AddBufferPresenceRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::AddBufferPresenceResponse rsp;
        (*on_add_buffer_presence_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddBufferPresenceResponse: {
      protobuf::AddBufferPresenceResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_add_buffer_presence_response_)(req);
      break;
    }

    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type, payload,
                                                          info, response,
                                                          timeout);
  }
}

}  // namespace maidsafe
