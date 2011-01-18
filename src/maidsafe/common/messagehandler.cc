/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class for processing RPC messages.
* Created:      2011-01-18
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

#include "maidsafe/common/chunk_messages.pb.h"
#include "maidsafe/common/chunk_info_messages.pb.h"
#include "maidsafe/common/account_messages.pb.h"
#include "maidsafe/common/vault_sync_messages.pb.h"
#include "maidsafe/common/buffer_messages.pb.h"

namespace maidsafe {

enum MessageType {
  // Chunk message types
  kArrangeStoreRequest = kademlia::kMaxMessageType + 1,
  kArrangeStoreResponse,
  kStoreChunkRequest,
  kStoreChunkResponse,
  kGetChunkRequest,
  kGetChunkResponse,
  kHasChunkRequest,
  kHasChunkResponse,
  kValidateChunkRequest,
  kValidateChunkResponse,
  kDeleteChunkRequest,
  kDeleteChunkResponse,
  kDuplicateChunkRequest,
  kDuplicateChunkResponse,
  kCacheChunkRequest,
  kCacheChunkResponse,
  // ChunkInfo message types
  kAddToWatchListRequest,
  kAddToWatchListResponse,
  kRemoveFromWatchListRequest,
  kRemoveFromWatchListResponse,
  kAddToReferenceListRequest,
  kAddToReferenceListResponse,
  kGetChunkReferencesRequest,
  kGetChunkReferencesResponse,
  // Account message types
  kAmendAccountRequest,
  kAmendAccountResponse,
  kExpectAmendmentRequest,
  kExpectAmendmentResponse,
  kAccountStatusRequest,
  kAccountStatusResponse,
  // VaultSync message types
  kGetSyncDataRequest,
  kGetSyncDataResponse,
  kGetAccountRequest,
  kGetAccountResponse,
  kGetChunkInfoRequest,
  kGetChunkInfoResponse,
  kGetBufferRequest,
  kGetBufferResponse,
  // Buffer message types
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
    const protobuf::ArrangeStoreRequest &msg) {
  return MakeSerialisedWrapperMessage(kArrangeStoreRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ArrangeStoreResponse &msg) {
  return MakeSerialisedWrapperMessage(kArrangeStoreResponse,
                                      msg.SerializeAsString());
}

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
    const protobuf::ValidateChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kValidateChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ValidateChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kValidateChunkResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::DeleteChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kDeleteChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::DeleteChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kDeleteChunkResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::DuplicateChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kDuplicateChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::DuplicateChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kDuplicateChunkResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::CacheChunkRequest &msg) {
  return MakeSerialisedWrapperMessage(kCacheChunkRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::CacheChunkResponse &msg) {
  return MakeSerialisedWrapperMessage(kCacheChunkResponse,
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
    case kArrangeStoreRequest: {
      protobuf::ArrangeStoreRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::ArrangeStoreResponse out_msg;
        (*on_arrange_store_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kArrangeStoreResponse: {
      protobuf::ArrangeStoreResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_arrange_store_response_)(in_msg);
      break;
    }

    case kStoreChunkRequest: {
      protobuf::StoreChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::StoreChunkResponse out_msg;
        (*on_store_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kStoreChunkResponse: {
      protobuf::StoreChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_store_chunk_response_)(in_msg);
      break;
    }

    case kGetChunkRequest: {
      protobuf::GetChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetChunkResponse out_msg;
        (*on_get_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetChunkResponse: {
      protobuf::GetChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_chunk_response_)(in_msg);
      break;
    }

    case kHasChunkRequest: {
      protobuf::HasChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::HasChunkResponse out_msg;
        (*on_has_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kHasChunkResponse: {
      protobuf::HasChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_has_chunk_response_)(in_msg);
      break;
    }

    case kValidateChunkRequest: {
      protobuf::ValidateChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::ValidateChunkResponse out_msg;
        (*on_validate_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kValidateChunkResponse: {
      protobuf::ValidateChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_validate_chunk_response_)(in_msg);
      break;
    }

    case kDeleteChunkRequest: {
      protobuf::DeleteChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::DeleteChunkResponse out_msg;
        (*on_delete_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kDeleteChunkResponse: {
      protobuf::DeleteChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_delete_chunk_response_)(in_msg);
      break;
    }

    case kDuplicateChunkRequest: {
      protobuf::DuplicateChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::DuplicateChunkResponse out_msg;
        (*on_duplicate_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kDuplicateChunkResponse: {
      protobuf::DuplicateChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_duplicate_chunk_response_)(in_msg);
      break;
    }

    case kCacheChunkRequest: {
      protobuf::CacheChunkRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::CacheChunkResponse out_msg;
        (*on_cache_chunk_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kCacheChunkResponse: {
      protobuf::CacheChunkResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_cache_chunk_response_)(in_msg);
      break;
    }

    case kAddToWatchListRequest: {
      protobuf::AddToWatchListRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::AddToWatchListResponse out_msg;
        (*on_add_to_watch_list_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddToWatchListResponse: {
      protobuf::AddToWatchListResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_add_to_watch_list_response_)(in_msg);
      break;
    }

    case kRemoveFromWatchListRequest: {
      protobuf::RemoveFromWatchListRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::RemoveFromWatchListResponse out_msg;
        (*on_remove_from_watch_list_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kRemoveFromWatchListResponse: {
      protobuf::RemoveFromWatchListResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_remove_from_watch_list_response_)(in_msg);
      break;
    }

    case kAddToReferenceListRequest: {
      protobuf::AddToReferenceListRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::AddToReferenceListResponse out_msg;
        (*on_add_to_reference_list_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddToReferenceListResponse: {
      protobuf::AddToReferenceListResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_add_to_reference_list_response_)(in_msg);
      break;
    }

    case kGetChunkReferencesRequest: {
      protobuf::GetChunkReferencesRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetChunkReferencesResponse out_msg;
        (*on_get_chunk_references_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetChunkReferencesResponse: {
      protobuf::GetChunkReferencesResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_chunk_references_response_)(in_msg);
      break;
    }

    case kAmendAccountRequest: {
      protobuf::AmendAccountRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::AmendAccountResponse out_msg;
        (*on_amend_account_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAmendAccountResponse: {
      protobuf::AmendAccountResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_amend_account_response_)(in_msg);
      break;
    }

    case kExpectAmendmentRequest: {
      protobuf::ExpectAmendmentRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::ExpectAmendmentResponse out_msg;
        (*on_expect_amendment_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kExpectAmendmentResponse: {
      protobuf::ExpectAmendmentResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_expect_amendment_response_)(in_msg);
      break;
    }

    case kAccountStatusRequest: {
      protobuf::AccountStatusRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::AccountStatusResponse out_msg;
        (*on_account_status_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAccountStatusResponse: {
      protobuf::AccountStatusResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_account_status_response_)(in_msg);
      break;
    }

    case kGetSyncDataRequest: {
      protobuf::GetSyncDataRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetSyncDataResponse out_msg;
        (*on_get_sync_data_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetSyncDataResponse: {
      protobuf::GetSyncDataResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_sync_data_response_)(in_msg);
      break;
    }

    case kGetAccountRequest: {
      protobuf::GetAccountRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetAccountResponse out_msg;
        (*on_get_account_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetAccountResponse: {
      protobuf::GetAccountResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_account_response_)(in_msg);
      break;
    }

    case kGetChunkInfoRequest: {
      protobuf::GetChunkInfoRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetChunkInfoResponse out_msg;
        (*on_get_chunk_info_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetChunkInfoResponse: {
      protobuf::GetChunkInfoResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_chunk_info_response_)(in_msg);
      break;
    }

    case kGetBufferRequest: {
      protobuf::GetBufferRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetBufferResponse out_msg;
        (*on_get_buffer_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetBufferResponse: {
      protobuf::GetBufferResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_buffer_response_)(in_msg);
      break;
    }

    case kCreateBufferRequest: {
      protobuf::CreateBufferRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::CreateBufferResponse out_msg;
        (*on_create_buffer_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kCreateBufferResponse: {
      protobuf::CreateBufferResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_create_buffer_response_)(in_msg);
      break;
    }

    case kModifyBufferInfoRequest: {
      protobuf::ModifyBufferInfoRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::ModifyBufferInfoResponse out_msg;
        (*on_modify_buffer_info_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kModifyBufferInfoResponse: {
      protobuf::ModifyBufferInfoResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_modify_buffer_info_response_)(in_msg);
      break;
    }

    case kGetBufferMessagesRequest: {
      protobuf::GetBufferMessagesRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetBufferMessagesResponse out_msg;
        (*on_get_buffer_messages_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetBufferMessagesResponse: {
      protobuf::GetBufferMessagesResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_buffer_messages_response_)(in_msg);
      break;
    }

    case kAddBufferMessageRequest: {
      protobuf::AddBufferMessageRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::AddBufferMessageResponse out_msg;
        (*on_add_buffer_message_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddBufferMessageResponse: {
      protobuf::AddBufferMessageResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_add_buffer_message_response_)(in_msg);
      break;
    }

    case kGetBufferPresenceRequest: {
      protobuf::GetBufferPresenceRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::GetBufferPresenceResponse out_msg;
        (*on_get_buffer_presence_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kGetBufferPresenceResponse: {
      protobuf::GetBufferPresenceResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_get_buffer_presence_response_)(in_msg);
      break;
    }

    case kAddBufferPresenceRequest: {
      protobuf::AddBufferPresenceRequest in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::AddBufferPresenceResponse out_msg;
        (*on_add_buffer_presence_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kAddBufferPresenceResponse: {
      protobuf::AddBufferPresenceResponse in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_add_buffer_presence_response_)(in_msg);
      break;
    }

    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type, payload,
                                                          info, response,
                                                          timeout);
  }
}

}  // namespace maidsafe
