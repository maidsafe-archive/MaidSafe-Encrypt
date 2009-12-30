/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  List of error codes
* Version:      1.0
* Created:      2009-10-12-13.48.44
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

#ifndef MAIDSAFE_RETURNCODES_H_
#define MAIDSAFE_RETURNCODES_H_

namespace maidsafe {

enum ReturnCode {
  // General
  kSuccess = 0,
  kGeneralError = -1,
  kIncorrectKeySize = -2,

  // Authentication
  kAuthenticationError = -1001,
  kPasswordFailure = -1002,
  kUserDoesntExist = -1003,
  kUserExists = -1004,
  kInvalidUsernameOrPin = -1005,
  kPublicUsernameExists = -1006,

  // Buffer Packet Handler
  kBPError = -2001,
  kBPSerialiseError = -2002,
  kBPInfoSerialiseError = -2003,
  kBPParseError = -2004,
  kBPInfoParseError = -2005,
  kStoreNewBPError = -2006,
  kModifyBPError = -2007,
  kBPAddUserError = -2008,
  kBPStoreAddedUserError = -2009,
  kBPDeleteUserError = -2010,
  kBPStoreDeletedUserError = -2011,
  kBPRetrievalError = -2012,
  kBPMessagesRetrievalError = -2013,
  kGetBPInfoError = -2014,
  kBPAddMessageError = -2015,
  kBPAwaitingCallback = -2016,

  // Chunkstore
  kInvalidChunkType = -127,
  kChunkstoreError = -3001,
  kChunkFileDoesntExist = -3003,
  kErrorReadingChunkFile = -3004,
  kChunkstoreUninitialised = -3005,
  kChunkstoreFailedStore = -3006,
  kChunkstoreFailedDelete = -3007,
  kChunkstoreException = -3008,
  kHashCheckFailure = -3009,
  kChunkExistsInChunkstore = 3001,  // intentionally positive

  // Client Controller
  kClientControllerError = -4001,
  kClientControllerNotInitialised = -4002,

  // Data Atlas Handler
  kDataAtlasError = -5001,
  kDBDoesntExist = -5002,
  kDBOpenException = -5003,
  kDBCreateException = -5004,
  kDBReadWriteException = -5005,
  kDBCloseException = -5006,
  kDBCantFindFile = -5007,
  kDBCantFindDirKey = -5008,
  kParseDataMapError = -5009,
  kAddElementError = -5010,
  kModifyElementError = -5011,
  kRemoveElementError = -5012,
  kRenameElementError = -5013,
  kCopyElementError = -5014,
  kDataAtlasException = -5015,

  // Key Atlas Handler
  kKeyAtlasError = -6001,

  // Store Manager
  kStoreManagerError = -7001,
  kNotConnected = -7002,
  kLoadChunkFindValueFailure = -7003,
  kPreSendFindValueFailure = -7004,
  kPreSendChunkAlreadyExists = -7005,
  kPreSendOverwriteCached = -7006,
  kChunkNotInChunkstore = -7007,
  kGetRequestSigError = -7008,
  kGetStorePeerError = -7009,
  kSendPrepFailure = -7010,
  kSendContentFailure = -7011,
  kStoreAlreadyCompleted = -7012,
  kStoreCancelled = -7013,
  kSendChunkFailure = -7014,
  kTaskCancelledOffline = -7015,
  kFindNodesError = -7016,
  kFindNodesFailure = -7017,
  kFindNodesParseError = -7018,
  kFindValueError = -7019,
  kFindValueFailure = -7020,
  kFindValueParseError = -7021,
  kLoadChunkFailure = -7022,
  kLoadedChunkEmpty = -7023,
  kGetChunkFailure = -7024,
  kDeleteSizeError = -7025,
  kSendPacketError = -7026,
  kSendPacketFailure = -7027,
  kSendPacketFindValueFailure = -7028,
  kSendPacketCached = -7029,
  kSendPacketParseError = -7030,
  kUpdateChunksFailure = -7031,
  kCommonChecksumUndecided = -7032,
  kCommonChecksumMajority = -7033,
  kPacketUnknownType = -7034,
  kLoadPacketFailure = -7035,
  kStoreManagerException = -7036,
  kFindAccountHoldersError = -7037,

  // Message Handler

  // Private Share Handler

  // Self Encryption Handler

  // Session
  kEmptyConversationId = -10001,
  kNonExistentConversation = -10002,
  kExistingConversation = -10003,
  kLoadKeysFailure = -10004,
  kContactListFailure = -10005,

  // Store Task Handler
  kStoreTaskHandlerError = -12001,
  kStoreTaskIncorrectParameter = -12002,
  kStoreTaskAlreadyExists = -12003,
  kStoreTaskNotFound = -12004,
  kStoreTaskNotFinished = -12005,
  kStoreTaskFinishedFail = -12006,
  kStoreTaskFinishedPass = 0  // intentionally 0
};

}  // namespace maidsafe

namespace maidsafe_vault {

enum ReturnCode {
  // General
  kSuccess = maidsafe::kSuccess,
  kGeneralError = maidsafe::kGeneralError,

  // Service
  kVaultServiceError = -1501,
  kVaultServiceUninitialisedFunction = -1502,

  // Vault
  kVaultOffline = -2501,

  // Vault Chunkstore
  kChunkstoreError = maidsafe::kChunkstoreError,
  kInvalidChunkType = maidsafe::kInvalidChunkType,
  kChunkstoreUninitialised = maidsafe::kChunkstoreUninitialised,
  kIncorrectKeySize = maidsafe::kIncorrectKeySize,
  kHashCheckFailure = maidsafe::kHashCheckFailure,
  kChunkstoreUpdateFailure = -3501,
  kPacketStoreValueExists = -3502,
  kPacketStoreFailure = -3503,
  kPacketAppendValueExists = -3504,
  kPacketAppendNotFound = -3505,
  kPacketAppendNotOwned = -3506,
  kPacketAppendFailure = -3507,
  kPacketOverwriteNotFound = -3508,
  kPacketOverwriteNotOwned = -3509,
  kPacketOverwriteFailure = -3510,
  kPacketDeleteNotFound = -3511,
  kPacketDeleteNotOwned = -3512,
  kPacketLoadNotFound = -3513,

  // Account Handler
  kAccountNotFound = -4501,
  kAccountExists = -4502,
  kAccountDeleteFailed = -4503,
  kAccountWrongAccountField = -4504,
  kAccountEmptyAlert = -4505,
  kAccountNotEnoughSpace = -4506,

  // Watch List Handler
  kWatchListInvalidChunkSize = -5501,
  kWatchListInvalidName = -5502

  // Vault Buffer Packet Handler
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_RETURNCODES_H_
