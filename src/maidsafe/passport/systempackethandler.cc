/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for manipulating database of system packets
* Version:      1.0
* Created:      14/10/2010 11:43:59
* Revision:     none
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

#include "maidsafe/passport/systempackethandler.h"
#include <cstdio>
#include "maidsafe/passport/passportreturncodes.h"
#include "maidsafe/passport/signaturepacket.pb.h"


namespace maidsafe {

namespace passport {

bool SystemPacketHandler::AddPacket(boost::shared_ptr<pki::Packet> packet,
                                    bool force) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<SystemPacketMap::iterator, bool> result =
      packets_.insert(SystemPacketMap::value_type(
          static_cast<PacketType>(packet->packet_type()), packet));
  if (!result.second) {
    if (force) {
      (*result.first).second = packet;
    } else {
#ifdef DEBUG
      printf("SystemPacketHandler::AddPacket: %s already in map.\n",
             DebugString(packet->packet_type()).c_str());
#endif
      return false;
    }
  }
  return true;
}

boost::shared_ptr<pki::Packet> SystemPacketHandler::Packet(
    const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::Packet: Don't have %s in map.\n",
            DebugString(packet_type).c_str());
#endif
    return boost::shared_ptr<pki::Packet>();
  }
  return (*it).second;
}

std::string SystemPacketHandler::SerialiseKeyring() {
  Keyring keyring;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.begin();
  while (it != packets_.end()) {
    if (IsSignature((*it).first, false)) {
      boost::shared_static_cast<SignaturePacket>((*it).second)->
          PutToKey(keyring.add_key());
    }
    ++it;
  }
  return keyring.SerializeAsString();
}

int SystemPacketHandler::ParseKeyring(const std::string &serialised_keyring) {
  Keyring keyring;
  if (!keyring.ParseFromString(serialised_keyring)) {
#ifdef DEBUG
    printf("SystemPacketHandler::ParseKeyring failed.\n");
#endif
    return kBadSerialisedKeyring;
  }
  boost::mutex::scoped_lock lock(mutex_);
  bool success(true);
  for (int i = 0; i < keyring.key_size(); ++i) {
    boost::shared_ptr<SignaturePacket> sig(new SignaturePacket(keyring.key(i)));
    success = success && AddPacket(sig, true);
  }
  return success ? kSuccess : kBadSerialisedKeyring;
}

void SystemPacketHandler::ClearKeyring() {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.begin();
  while (it != packets_.end()) {
    if (IsSignature((*it).first, false)) {
      packets_.erase(it++);
    } else {
      ++it;
    }
  }
}


/*
int KeyAtlas::AddKey(const int &packet_type,
                     const std::string &packet_id,
                     const std::string &private_key,
                     const std::string &public_key,
                     const std::string &signed_public_key) {
  KeyAtlasSet::iterator it = key_ring_.find(packet_type);
  if (it != key_ring_.end())
    key_ring_.erase(packet_type);
  std::string signed_pub_key = signed_public_key;
  if (signed_pub_key.empty())
    signed_pub_key = co_.AsymSign(public_key, "", private_key,
                                  crypto::STRING_STRING);
  KeyAtlasRow kar(packet_type, packet_id, private_key, public_key,
                  signed_pub_key);
  std::pair<KeyAtlasSet::iterator, bool> p = key_ring_.insert(kar);
  if (p.second)
    return kSuccess;
  return kKeyAtlasError;
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
  KeyAtlasSet::iterator it = key_ring_.find(packet_type);
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
  KeyAtlasSet::iterator it = key_ring_.find(packet_type);
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
  KeyAtlasSet::iterator it;
  for (it = key_ring_.begin(); it != key_ring_.end(); it++) {
    KeyAtlasRow kar((*it).type_, (*it).id_, (*it).private_key_,
                    (*it).public_key_, (*it).signed_public_key_);
    keyring->push_back(kar);
  }
}

unsigned int KeyAtlas::KeyRingSize() { return key_ring_.size(); }

void KeyAtlas::ClearKeyRing() { key_ring_.clear(); }
*/
}  // namespace passport

}  // namespace maidsafe
