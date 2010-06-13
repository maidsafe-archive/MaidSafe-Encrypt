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
  kUndefined = -3,
  kPendingResult = -4,

  // Authentication
  kAuthenticationError = -1001,
  kPasswordFailure = -1002,
  kUserDoesntExist = -1003,
  kUserExists = -1004,
  kInvalidUsernameOrPin = -1005,
  kPublicUsernameExists = -1006,
  kAuthenticationTimeout = -1007,

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
  kBPGetPresenceError = -2017,
  kBPAddPresenceError = -2018,

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

  // Store Managers
  kStoreManagerError = -7001,
  kStoreManagerInitError = -7002,
  kNotConnected = -7002,
  kLoadChunkFindNodesFailure = -7003,
  kStoreChunkFindNodesFailure = -7004,
  kStoreChunkError = -7005,
  kStoreCancelledOrDone = -7006,
  kChunkNotInChunkstore = -7007,
  kGetRequestSigError = -7008,
  kGetStorePeerError = -7009,
  kSendPrepResponseUninitialised = -7010,
  kSendPrepPeerError = -7011,
  kSendPrepSignedSizeAltered = -7012,
  kSendPrepFailure = -7013,
  kSendPrepInvalidId = -7014,
  kSendPrepInvalidResponseSignature = -7015,
  kSendPrepInvalidContractSignature = -7016,
  kSendContentFailure = -7017,
  kSendChunkFailure = -7018,
  kTaskCancelledOffline = -7019,
  kFindNodesError = -7020,
  kFindNodesFailure = -7021,
  kFindNodesParseError = -7022,
  kFindValueError = -7023,
  kFindValueFailure = -7024,
  kFindValueParseError = -7025,
  kLoadChunkFailure = -7026,
  kDeleteChunkFindNodesFailure = -7027,
  kDeleteChunkError = -7028,
  kDeleteSizeError = -7029,
  kDeleteChunkFailure = -7030,
  kDeleteCancelledOrDone = -7031,
  kLoadedChunkEmpty = -7032,
  kGetChunkFailure = -7033,
  kSendPacketError = -7034,
  kSendPacketFailure = -7035,
  kSendPacketFindValueFailure = -7036,
  kSendPacketCached = -7037,
  kSendPacketAlreadyExists = -7038,
  kSendPacketUnknownExistsType = -7039,
  kSendPacketParseError = -7040,
  kDeletePacketFindValueFailure = -7041,
  kDeletePacketError = -7042,
  kDeletePacketParseError = -7043,
  kDeletePacketFailure = -7044,
  kLoadPacketCached = -7045,
  kLoadPacketFailure = -7046,
  kPacketUnknownType = -7047,
  kDirUnknownType = -7048,
  kStoreManagerException = -7049,
  kFindAccountHoldersError = -7050,
  kRequestPendingConsensus = -7051,
  kRequestFailedConsensus = -7052,
  kRequestInsufficientResponses = -7053,
  kNoPublicKeyToCheck = -7054,
  kKeyUnique = -7055,
  kKeyNotUnique = -7056,
  kUpdatePacketFailure = -7057,
  kUpdatePacketError = -7058,
  kUpdatePacketParseError = -7059,

  // KadOps
  kKadConfigException = -8001,
  kKadOpsInitFailure = -8002,
  kKadIdError = -8003,

  // Message Handler
  kConnectionNotExists = -9001,
  kFailedToConnect = -9002,
  kFailedToSend = -9003,
  kFailedToStartHandler = -9004,
  kHandlerAlreadyStarted = -9005,
  kHandlerNotStarted = -9006,
  kConnectionAlreadyExists = -9007,
  kConnectionDown = -9008,

  // Private Share Handler (-10000)

  // Session & FileSystem
  kEmptyConversationId = -11001,
  kNonExistentConversation = -11002,
  kExistingConversation = -11003,
  kLoadKeysFailure = -11004,
  kContactListFailure = -11005,
  kSessionNameEmpty = -11006,
  kFileSystemMountError = -11007,
  kFileSystemUnmountError = -11008,
  kFuseMountPointError = -11009,
  kFileSystemException = -11010,
  kAddLiveContactFailure = -11011,
  kLiveContactNotFound = -11012,
  kLiveContactNoEp = -11013,


  // Self Encryption Handler (-12000)

  // Store Task Handler
  kStoreTaskHandlerError = -13001,
  kStoreTaskIncorrectParameter = -13002,
  kStoreTaskAlreadyExists = -13003,
  kStoreTaskNotFound = -13004,
  kStoreTaskNotFinished = -13005,
  kStoreTaskFinishedFail = -13006,
  kStoreTaskFinishedPass = 0,  // intentionally 0

  // Validator
  kValidatorNoParameters = -14001,
  kValidatorNoPrivateKey = -14002
};

}  // namespace maidsafe

namespace maidsafe_vault {

enum ReturnCode {
  // General
  kSuccess = maidsafe::kSuccess,
  kGeneralError = maidsafe::kGeneralError,
  kVaultOffline = -501,

  // Service
  kVaultServiceError = -1501,
  kVaultServiceUninitialisedFunction = -1502,
  kVaultServiceFindNodesError = -1503,
  kVaultServiceFindNodesFailure = -1504,
  kVaultServiceFindNodesTooFew = -1505,
  kRemoteOpResponseUninitialised = -1506,
  kRemoteOpResponseFailed = -1507,
  kRemoteOpResponseError = -1508,
  kCacheChunkResponseUninitialised = -1509,
  kCacheChunkResponseError = -1510,

  // Vault
  kVaultDaemonException = -2501,
  kVaultDaemonWaitingPwnage = -2502,
  kVaultDaemonParseError = -2503,
  kVaultDaemonConfigError = -2504,

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
  kPacketDeleteNotFound = -3508,
  kPacketDeleteNotOwned = -3509,
  kPacketLoadNotFound = -3510,
  kNoSpaceForCaching = -3511,
  kNoCacheSpaceToClear = -3512,

  // Account Handler & Account Amendment Handler & Request Expectation Handler
  kAccountHandlerNotStarted = -4501,
  kAccountNotFound = -4502,
  kAccountExists = -4503,
  kAccountDeleteFailed = -4504,
  kAccountWrongAccountField = -4505,
  kAccountEmptyAlert = -4506,
  kAccountNotEnoughSpace = -4507,
  kAmendAccountTypeError = -4508,
  kAmendAccountCountError = -4509,
  kAccountAmendmentError = -4510,
  kAccountAmendmentPending = -4511,
  kAccountAmendmentNotFound = -4512,
  kAccountAmendmentUpdated = -4513,
  kAccountAmendmentFinished = -4514,
  kRequestExpectationCountError = -4515,

  // Chunk Info Handler
  kChunkInfoHandlerNotStarted = -5501,
  kChunkInfoInvalidSize = -5502,
  kChunkInfoInvalidName = -5503,
  kChunkInfoCannotDelete = -5504,
  kChunkInfoExists = -5505,
  kChunkInfoNoActiveWatchers = -5506

  // Vault Buffer Packet Handler
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_RETURNCODES_H_
