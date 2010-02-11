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

#ifndef MAIDSAFE_CLIENT_KEYATLAS_H_
#define MAIDSAFE_CLIENT_KEYATLAS_H_

#include <boost/multi_index_container.hpp>
#include <boost/shared_ptr.hpp>

#include <list>
#include <string>

#include "maidsafe/maidsafe.h"

namespace maidsafe {

struct KeyAtlasRow {
  KeyAtlasRow(int type, const std::string &id,
              const std::string &private_key,
              const std::string &public_key,
              const std::string &signed_public_key)
              : type_(type), id_(id), private_key_(private_key),
              public_key_(public_key), signed_public_key_(signed_public_key) { }
  int type_;
  std::string id_;
  std::string private_key_;
  std::string public_key_;
  std::string signed_public_key_;
};

typedef boost::multi_index_container<
  KeyAtlasRow,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      BOOST_MULTI_INDEX_MEMBER(KeyAtlasRow, int, type_)
    >
  >
> KeyAtlasSet;

class KeyAtlas {
 public:
  KeyAtlas();
  ~KeyAtlas();
  // If signed_public_key == "", it is set as signature of given public_key
  // using given private_key.
  int AddKey(const int &packet_type,
             const std::string &packet_id,
             const std::string &private_key,
             const std::string &public_key,
             const std::string &signed_public_key);
  std::string PackageID(const int &packet_type);
  std::string PrivateKey(const int &packet_type);
  std::string PublicKey(const int &packet_type);
  std::string SignedPublicKey(const int &packet_type);
  int RemoveKey(const int &packet_type);
  void GetKeyRing(std::list<KeyAtlasRow> *keyring);
  unsigned int KeyRingSize();
  void ClearKeyRing();

 private:
  std::string SearchKeyring(const int &packet_type, const int &field);
  KeyAtlasSet key_ring_;
  crypto::Crypto co_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_KEYATLAS_H_

