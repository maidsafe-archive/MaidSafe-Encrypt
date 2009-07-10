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

#include "maidsafe/client/keyatlas.h"

#include <stdint.h>

#include <boost/filesystem.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <exception>
#include <map>

#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"
#include "protobuf/datamaps.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

KeyAtlas::KeyAtlas() : key_ring_() {}
KeyAtlas::~KeyAtlas() {}

int KeyAtlas::AddKey(const int &package_type, const std::string &package_id,
    const std::string &private_key, const std::string &public_key) {
  key_ring_.erase(package_type);
  KeyAtlasRow kar(package_type, package_id, private_key, public_key);
  key_atlas_set::iterator  it = key_ring_.find(package_type);
  key_ring_.insert(kar);
  return 0;
}

std::string KeyAtlas::SearchKeyring(const int &package_type,
                                    const int &field) {
  std::string result;
  if (field < 1 || field > 3) {
#ifdef DEBUG
    printf("Wrong column(%d)\n", field);
#endif
    return result;
  }
  key_atlas_set::iterator  it = key_ring_.find(package_type);
  if (it == key_ring_.end()) {
#ifdef DEBUG
    printf("Key type(%d) not present in keyring\n", package_type);
#endif
    return result;
  }
  switch (field) {
    case 1: result = (*it).id_; break;
    case 2: result = (*it).private_key_; break;
    case 3: result = (*it).public_key_; break;
  }
  return result;
}

std::string KeyAtlas::PackageID(const int &package_type) {
  return SearchKeyring(package_type, 1);
}

std::string KeyAtlas::PrivateKey(const int &package_type) {
  return SearchKeyring(package_type, 2);
}

std::string KeyAtlas::PublicKey(const int &package_type) {
  return SearchKeyring(package_type, 3);
}

int KeyAtlas::RemoveKey(const int &package_type) {
  key_atlas_set::iterator it = key_ring_.find(package_type);
  if (it == key_ring_.end()) {
#ifdef DEBUG
    printf("Key type(%d) not present in keyring.\n", package_type);
#endif
    return -1801;
  }
  key_ring_.erase(package_type);
  return 0;
}

void KeyAtlas::GetKeyRing(std::list<KeyAtlasRow> *keyring) {
  keyring->clear();
  key_atlas_set::iterator it;
  for (it = key_ring_.begin(); it != key_ring_.end(); it++) {
    KeyAtlasRow kar((*it).type_, (*it).id_, (*it).private_key_,
                   (*it).public_key_);
    keyring->push_back(kar);
  }
}

unsigned int KeyAtlas::KeyRingSize() { return key_ring_.size(); }

void KeyAtlas::ClearKeyRing() { key_ring_.clear(); }

}  // namespace maidsafe
