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

#ifndef MAIDSAFE_COMMON_RETURNCODES_H_
#define MAIDSAFE_COMMON_RETURNCODES_H_

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
//  kInvalidUsernameOrPin = -1005,
  kPublicUsernameExists = -1006,
  kPublicUsernameAlreadySet = -1007,
//  kAuthenticationTimeout = -1007,
  kFailedToDeleteOldPacket = -1008,
  kBadPacket = -1009,

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

  // Store Managers
  kStoreManagerError = -7001,
  kStoreManagerInitError = -7002,
  kNotConnected = -7002,
  kLoadChunkFindNodesFailure = -7003,
  kStoreChunkFindNodesFailure = -7004,
  kStoreChunkError = -7005,
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
  kChunkStorePending = -7060,
  kAmendAccountFailure = -7061,

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
  kGetKeyFailure = -11005,
  kContactListFailure = -11006,
  kSessionNameEmpty = -11007,
  kFileSystemMountError = -11008,
  kFileSystemUnmountError = -11009,
  kFuseMountPointError = -11010,
  kFileSystemException = -11011,
  kAddLiveContactFailure = -11012,
  kLiveContactNotFound = -11013,
  kLiveContactNoEp = -11014,

  // Self Encryption Handler (-12000)
  kGeneralEncryptionError = -12001,
  kEncryptFileFailure = -12002,
  kEncryptStringFailure = -12003,
  kEncryptDbFailure = -12004,
  kDecryptFileFailure = -12005,
  kDecryptStringFailure = -12006,
  kDecryptDbFailure = -12007,
  kEncryptionLocked = -12008,
  kEncryptionLink = -12009,
  kEncryptionChunk = -12010,
  kEncryptionNotForProcessing = -12011,
  kEncryptionUnknownType = -12012,
  kEncryptionMDMFailure = -12013,
  kEncryptionDAHFailure = -12014,
  kEncryptionDMFailure = -12015,
  kEncryptionSMFailure = -12016,
  kEncryptionSmallInput = -12017,
  kEncryptionKeyGenFailure = -12018,
  kEncryptionGetDirKeyFailure = -12019,
  kEncryptionDbMissing = -12020,
  kEncryptionDbException = -12021,
  kEncryptionDmNotInMap = -12022,

  // Store Manager Task Handler
  kStoreManagerTaskHandlerError = -13001,
  kStoreManagerTaskIncorrectParameter = -13002,
  kStoreManagerTaskIncorrectOperation = -13003,
  kStoreManagerTaskParentNotActive = -13004,
  kStoreManagerTaskNotFound = -13005,
  kStoreManagerTaskCancelledOrDone = -13006,

  // Validator
  kValidatorNoParameters = -14001,
  kValidatorNoPrivateKey = -14002
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_RETURNCODES_H_
