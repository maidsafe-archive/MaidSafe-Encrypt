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

#ifndef MAIDSAFE_PASSPORT_PASSPORTRETURNCODES_H_
#define MAIDSAFE_PASSPORT_PASSPORTRETURNCODES_H_

namespace maidsafe {

namespace passport {

enum ReturnCode {
  kSuccess = 0,
//  kGeneralError = -1,
//  kSystemPacketHandlerError = -1001,

  kPassportError = -1001,
  kNoMid = -1002,
  kNoSmid = -1003,
  kNoStmid = -1004,
  kNoTmid = -1005,
  kBadSerialisedMidRid = -1006,
  kBadSerialisedSmidRid = -1007,
  kBadSerialisedTmidData = -1008,
  kBadSerialisedStmidData = -1009,
//  kPasswordFailure = -1002,
//  kUserDoesntExist = -1003,
//  kUserExists = -1004,
//  kInvalidUsernameOrPin = -1005,
//  kPublicUsernameExists = -1006,
//  kAuthenticationTimeout = -1007
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORTRETURNCODES_H_
