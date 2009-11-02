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
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <exception>
#include <map>

#include "protobuf/datamaps.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

KeyAtlas::KeyAtlas() : key_ring_(), co_() {}
KeyAtlas::~KeyAtlas() {}

int KeyAtlas::AddKey(const int &packet_type,
                     const std::string &packet_id,
                     const std::string &private_key,
                     const std::string &public_key,
                     const std::string &signed_public_key) {
  key_atlas_set::iterator  it = key_ring_.find(packet_type);
  if (it != key_ring_.end())
    key_ring_.erase(packet_type);
  std::string signed_pub_key = signed_public_key;
  if (signed_pub_key == "")
    signed_pub_key = co_.AsymSign(public_key, "", private_key,
                                  crypto::STRING_STRING);
  KeyAtlasRow kar(packet_type, packet_id, private_key, public_key,
                  signed_pub_key);
  key_ring_.insert(kar);
  return kSuccess;
}

std::string KeyAtlas::SearchKeyring(const int &packet_type,
                                    const int &field) {
  std::string result;
  if (field < 1 || field > 4) {
#ifdef DEBUG
    printf("Wrong column(%d)\n", field);
#endif
    return result;
  }
  key_atlas_set::iterator  it = key_ring_.find(packet_type);
  if (it == key_ring_.end()) {
#ifdef DEBUG
    printf("Key type(%d) not present in keyring\n", packet_type);
#endif
    return result;
  }
  switch (field) {
    case 1: result = (*it).id_; break;
    case 2: result = (*it).private_key_; break;
    case 3: result = (*it).public_key_; break;
    case 4: result = (*it).signed_public_key_; break;
  }
  return result;
}

std::string KeyAtlas::PackageID(const int &packet_type) {
  return SearchKeyring(packet_type, 1);
}

std::string KeyAtlas::PrivateKey(const int &packet_type) {
  return SearchKeyring(packet_type, 2);
}

std::string KeyAtlas::PublicKey(const int &packet_type) {
  return SearchKeyring(packet_type, 3);
}

std::string KeyAtlas::SignedPublicKey(const int &packet_type) {
  return SearchKeyring(packet_type, 4);
}

int KeyAtlas::RemoveKey(const int &packet_type) {
  key_atlas_set::iterator it = key_ring_.find(packet_type);
  if (it == key_ring_.end()) {
#ifdef DEBUG
    printf("Key type(%d) not present in keyring.\n", packet_type);
#endif
    return kKeyAtlasError;
  }
  key_ring_.erase(packet_type);
  return kSuccess;
}

void KeyAtlas::GetKeyRing(std::list<KeyAtlasRow> *keyring) {
  keyring->clear();
  key_atlas_set::iterator it;
  for (it = key_ring_.begin(); it != key_ring_.end(); it++) {
    KeyAtlasRow kar((*it).type_, (*it).id_, (*it).private_key_,
                    (*it).public_key_, (*it).signed_public_key_);
    keyring->push_back(kar);
  }
}

unsigned int KeyAtlas::KeyRingSize() { return key_ring_.size(); }

void KeyAtlas::ClearKeyRing() { key_ring_.clear(); }

}  // namespace maidsafe
