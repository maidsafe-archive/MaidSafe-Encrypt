/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Singleton for setting/getting session info
* Created:      2010-02-18
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

#ifndef MAIDSAFE_SHAREDTEST_MOCKSESSIONSINGLETON_H_
#define MAIDSAFE_SHAREDTEST_MOCKSESSIONSINGLETON_H_

#include "maidsafe/client/sessionsingleton.h"

namespace maidsafe {

class MockSessionSingleton : public SessionSingleton {
 public:
  MockSessionSingleton() {}
  ~MockSessionSingleton() {}
};

}  // namespace maidsafe

#endif  // MAIDSAFE_SHAREDTEST_MOCKSESSIONSINGLETON_H_
