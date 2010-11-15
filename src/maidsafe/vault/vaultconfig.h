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

#ifndef MAIDSAFE_VAULT_VAULTRETURNCODES_H_
#define MAIDSAFE_VAULT_VAULTRETURNCODES_H_

#include <boost/function.hpp>

#include "maidsafe/common/returncodes.h"

namespace maidsafe {

namespace vault {

enum VaultReturnCode {
  // General
  kSuccess = maidsafe::kSuccess,
  kGeneralError = maidsafe::kGeneralError,
  kPendingResult = maidsafe::kPendingResult,
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
  kAccountInvalidAmount = -4508,
  kAmendAccountTypeError = -4509,
  kAmendAccountCountError = -4510,
  kAccountAmendmentError = -4511,
  kAccountAmendmentPending = -4512,
  kAccountAmendmentNotFound = -4513,
  kAccountAmendmentUpdated = -4514,
  kAccountAmendmentFinished = -4515,
  kRequestExpectationCountError = -4516,

  // Chunk Info Handler
  kChunkInfoHandlerNotStarted = -5501,
  kChunkInfoInvalidSize = -5502,
  kChunkInfoInvalidName = -5503,
  kChunkInfoCannotDelete = -5504,
  kChunkInfoExists = -5505,
  kChunkInfoNoActiveWatchers = -5506,
  kChunkInfoRefExists = -5507

  // Vault Buffer Packet Handler
};

typedef boost::function<void(const VaultReturnCode&)> VoidFuncOneInt;

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_VAULTRETURNCODES_H_
