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

  // Chunkstore
  kInvalidChunkType = -127,
  kChunkstoreError = -3001,
  kChunkFileDoesntExist = -3003,
  kErrorReadingChunkFile = -3004,
  kChunkstoreUninitialised = -3005,
  kIncorrectKeySize = -3006,
  kChunkstoreFailedStore = -3007,
  kChunkstoreFailedDelete = -3008,
  kChunkstoreException = -3009,
  kFailedHashCheck = -3010,
  kChunkExistsInChunkstore = 3001  // intentionally positive

  // Client Controller

  // Data Atlas Handler

  // Key Atlas Handler

  // Store Manager

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

  // Vault Buffer Packet Handler

  // Vault Chunkstore
  kChunkstoreError = maidsafe::kChunkstoreError,
  kInvalidChunkType = maidsafe::kInvalidChunkType,
  kChunkstoreUninitialised = maidsafe::kChunkstoreUninitialised,
  kIncorrectKeySize = maidsafe::kIncorrectKeySize,
  kFailedHashCheck = maidsafe::kFailedHashCheck,
  kChunkstoreFailedUpdate = -3501
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_RETURNCODES_H_
