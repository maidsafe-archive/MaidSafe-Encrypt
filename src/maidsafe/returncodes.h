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

  // Data Atlas Handler
  kDataAtlasError = -4001,
  kDBDoesntExist = -4002,
  kDBOpenException = -4003,
  kDBCreateException = -4004,
  kDBReadWriteException = -4005,
  kDBCloseException = -4006,
  kDBCantFindFile = -4007,
  kDBCantFindDirKey = -4008,
  kParseDataMapError = -4009,
  kAddElementError = -4010,
  kModifyElementError = -4011,
  kRemoveElementError = -4012,
  kRenameElementError = -4013,
  kCopyElementError = -4014,
  kDataAtlasException = -4015,

  // Key Atlas Handler
  kKeyAtlasError = -5001,

  // Store Manager
  kStoreManagerError = -6001,
  kNotConnected = -6002,
  kLoadChunkFindValueFailure = -6003,
  kPreSendFindValueFailure = -6004,
  kPreSendChunkAlreadyExists = -6005,
  kPreSendOverwriteCached = -6006,
  kChunkNotInChunkstore = -6007,
  kGetRequestSigError = -6008,
  kGetStorePeerError = -6009,
  kSendPrepFailure = -6010,
  kSendContentFailure = -6011,
  kIOUsSerialiseError = -6012,
  kStoreIOUsFindNodesFailure = -6013,
  kStoreIOUsFailure = -6014,
  kFindNodesError = -6015,
  kFindNodesFailure = -6016,
  kFindNodesParseError = -6017,
  kFindValueError = -6018,
  kFindValueFailure = -6019,
  kFindValueParseError = -6020,
  kLoadChunkFailure = -6021,
  kLoadedChunkEmpty = -6022,
  kGetChunkFailure = -6023,
  kStoreIOUFailure = -6024,
  kSendIOUDoneFailure = -6025,
  kSendPacketError = -6026,
  kSendPacketFailure = -6027,
  kSendPacketFindValueFailure = -6028,
  kSendPacketCached = -6029,
  kSendPacketParseError = -6030,
  kUpdateChunksFailure = -6031,
  kCommonChecksumUndecided = -6032,
  kCommonChecksumMajority = -6033,
  kPacketUnknownType = -6034,
  kLoadPacketFailure = -6035,
  kStoreManagerException = -6036,

  // Message Handler

  // Private Share Handler

  // Self Encryption Handler

  // Session
};

}  // namespace maidsafe

namespace maidsafe_vault {

enum ReturnCode {
  // General
  kSuccess = maidsafe::kSuccess,
  kGeneralError = maidsafe::kGeneralError,

  // Service

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
  kPacketLoadNotFound = -3513

  // Vault Buffer Packet Handler
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_RETURNCODES_H_
