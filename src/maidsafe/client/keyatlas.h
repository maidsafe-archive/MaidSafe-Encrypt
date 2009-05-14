/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class for manipulating database of user keys
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
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


// Table key:-
// -----------
// type (int)
// id (char(64))
// private_key (varchar(2048))
// public_key (varchar(2048))
// primary key(type)


#ifndef MAIDSAFE_CLIENT_KEYATLAS_H_
#define MAIDSAFE_CLIENT_KEYATLAS_H_

#include <list>
#include <string>

#include "boost/shared_ptr.hpp"

#include "base/cppsqlite3.h"
#include "maidsafe/maidsafe.h"

namespace maidsafe {

class KeyAtlas {
 public:
  KeyAtlas(const std::string &db_name, db_init_flag flag_, int *result_);
  ~KeyAtlas();
  int AddKeys(const std::string &package_type,
              const std::string &package_id,
              const std::string &private_key,
              const std::string &public_key);
  std::string GetPackageID(const std::string &packet_type);
  std::string GetPrivateKey(const std::string &packet_type);
  std::string GetPublicKey(const std::string &packet_type);
  int RemoveKeys(const std::string &package_type);
  // GetKeyRing (only keys and id's of predifined sys packets
  // (ANMID, MAID, etc) List of structs
  void GetKeyRing(std::list<Key_Type> *keyring);

 private:
  int Init(db_init_flag flag_);
  std::string GetKeyData(const std::string &package_type, char data_type);
  int ConnectKeysDb();
  int CreateKeysDb();
  int DisconnectKeysDb();
  std::string db_name_;
  boost::shared_ptr<CppSQLite3DB> db_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_KEYATLAS_H_

