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
  kPassportError = -100001,
  kNoMid = -100002,
  kNoSmid = -100003,
  kNoStmid = -100004,
  kNoTmid = -100005,
  kNoSigningPacket = -100006,
  kBadSerialisedMidRid = -100007,
  kBadSerialisedSmidRid = -100008,
  kBadSerialisedTmidData = -100009,
  kBadSerialisedStmidData = -100010,
  kBadSerialisedKeyring = -100011
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORTRETURNCODES_H_
