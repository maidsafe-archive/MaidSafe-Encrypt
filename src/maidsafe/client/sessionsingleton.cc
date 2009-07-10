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
#include "protobuf/datamaps.pb.h"

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
//  buffer_packet_type ids[3] = {MPID_BP, PMID_BP, MAID_BP};
//  for (int i = 0; i < 3; ++i) {
//    SetPrivateKey("", ids[i]);
//    SetId("", ids[i]);
//    SetPublicKey("", ids[i]);
//  }
  SetMounted(0);
  SetWinDrive('\0');
  ka_.ClearKeyRing();
  return true;
}

int SessionSingleton::LoadKeys(std::list<Key> *keys) {
  if (keys->empty())
    return -1900;

  int n = 0;
  while (!keys->empty()) {
    Key k = keys->front();
    keys->pop_front();
    AddKey(k.type(), k.id(), k.private_key(), k.public_key());
    ++n;
  }

//  // MAID
//  if (ka_.PackageID(3) != "") {
//    SetPublicKey(ka_.PublicKey(3), MAID_BP);
//    SetPublicKey(ka_.PrivateKey(3), MAID_BP);
//  }
//  // PMID
//  if (ka_.PackageID(4) != "") {
//    SetPublicUsername(ka_.PackageID(4));
//    SetPublicKey(ka_.PublicKey(4), PMID_BP);
//    SetPublicKey(ka_.PrivateKey(4), PMID_BP);
//  }

  return n;
}

void SessionSingleton::GetKeys(std::list<KeyAtlasRow> *keys) {
  keys->clear();
  ka_.GetKeyRing(keys);
}

void SessionSingleton::SerialisedKeyRing(std::string *ser_kr) {
  DataAtlas da;
  std::list<KeyAtlasRow> keys;
  GetKeys(&keys);
  while (!keys.empty()) {
    KeyAtlasRow kar = keys.front();
    Key *k = da.add_keys();
    k->set_type(PacketType(kar.type_));
    k->set_id(kar.id_);
    k->set_private_key(kar.private_key_);
    k->set_public_key(kar.public_key_);
    keys.pop_front();
  }
  da.SerializeToString(ser_kr);
}

void SessionSingleton::AddKey(const PacketType &pt,
                              const std::string &id,
                              const std::string &private_key,
                              const std::string &public_key) {
  ka_.AddKey(pt, id, private_key, public_key);
}

std::string SessionSingleton::Id(const PacketType &pt) {
  return ka_.PackageID(pt);
}

std::string SessionSingleton::PublicKey(const PacketType &pt) {
  return ka_.PublicKey(pt);
}

std::string SessionSingleton::PrivateKey(const PacketType &pt) {
  return ka_.PrivateKey(pt);
}

}  // namespace maidsafe


