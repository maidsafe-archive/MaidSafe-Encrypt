/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton for setting/getting session info
* Version:      1.0
* Created:      2009-01-28-16.56.20
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

#include "maidsafe/client/sessionsingleton.h"

namespace maidsafe {

SessionSingleton* SessionSingleton::single = 0;
boost::mutex ss_mutex;

SessionSingleton *SessionSingleton::getInstance() {
  if (single == 0) {
    boost::mutex::scoped_lock lock(ss_mutex);
    if (single == 0)
      single = new SessionSingleton();
  }
  return single;
}

void SessionSingleton::Destroy() {
  delete single;
  single = 0;
}

bool SessionSingleton::ResetSession() {
  SetDaModified(false);
  SetDefConLevel(DEFCON3);
  SetUsername("");
  SetPin("");
  SetPassword("");
  SetMidRid(0);
  SetSmidRid(0);
  SetSessionName(true);
  SetRootDbKey("");
  std::set<std::string> empty_set;
  SetAuthorisedUsers(empty_set);
  SetMaidAuthorisedUsers(empty_set);
  buffer_packet_type ids[3] = {MPID_BP, PMID_BP, MAID_BP};
  for (int i = 0; i < 3; ++i) {
    SetPrivateKey("", ids[i]);
    SetId("", ids[i]);
    SetPublicKey("", ids[i]);
  }
  SetMounted(0);
  SetWinDrive('\0');
  return true;
}

}  // namespace maidsafe


