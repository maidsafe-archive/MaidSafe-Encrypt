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
#include "maidsafe/passport/passportconfig.h"
#include "maidsafe/passport/signaturepacket.pb.h"


namespace maidsafe {

namespace passport {

bool SystemPacketHandler::AddPacket(std::tr1::shared_ptr<pki::Packet> packet) {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it =
      packets_.find(static_cast<PacketType>(packet->packet_type()));
  if (it == packets_.end()) {
    std::pair<SystemPacketMap::iterator, bool> result =
        packets_.insert(SystemPacketMap::value_type(
            static_cast<PacketType>(packet->packet_type()),
            PacketInfo(packet)));
#ifdef DEBUG
    if (!result.second)
      printf("SystemPacketHandler::AddPacket: Failed for %s.\n",
              DebugString(packet->packet_type()).c_str());
#endif
    return result.second;
  } else {
    (*it).second.pending = packet;
    return true;
  }
}

bool SystemPacketHandler::ConfirmPacket(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::ConfirmPacket: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
    return false;
  }
  bool dependencies_confirmed(true);
  switch (packet_type) {
    case MID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANMID));
      break;
    case SMID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANSMID));
      break;
    case TMID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANTMID)) &&
                               IsConfirmed(packets_.find(MID)) &&
                               IsConfirmed(packets_.find(ANMID));
      break;
    case STMID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANTMID)) &&
                               IsConfirmed(packets_.find(SMID)) &&
                               IsConfirmed(packets_.find(ANSMID));
      break;
    case MPID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANMPID));
      break;
    case PMID:
      dependencies_confirmed = IsConfirmed(packets_.find(MAID)) &&
                               IsConfirmed(packets_.find(ANMAID));
      break;
    case MAID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANMAID));
      break;
    default:
      break;
  }
  if (!dependencies_confirmed) {
#ifdef DEBUG
    printf("SystemPacketHandler::ConfirmPacket: dependencies for %s not "
           "confirmed.\n", DebugString(packet_type).c_str());
#endif
    return false;
  } else {
    (*it).second.stored = (*it).second.pending;
    (*it).second.pending.reset();
    return true;
  }
}

bool SystemPacketHandler::RevertPacket(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::RevertPacket: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
    return false;
  } else {
    (*it).second.pending.reset();
    return true;
  }
}

std::tr1::shared_ptr<pki::Packet> SystemPacketHandler::Packet(
    const PacketType &packet_type) {
  return GetPacket(packet_type, true);
}

std::tr1::shared_ptr<pki::Packet> SystemPacketHandler::PendingPacket(
    const PacketType &packet_type) {
  return GetPacket(packet_type, false);
}

std::tr1::shared_ptr<pki::Packet> SystemPacketHandler::GetPacket(
    const PacketType &packet_type,
    bool confirmed) {
  std::tr1::shared_ptr<pki::Packet> packet;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::Packet: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
  } else {
    std::tr1::shared_ptr<pki::Packet> retrieved_packet;
    if (confirmed && (*it).second.stored.get()) {
      retrieved_packet = (*it).second.stored;
    } else if (!confirmed && (*it).second.pending.get()) {
      retrieved_packet = (*it).second.pending;
    }
    if (retrieved_packet.get()) {
      // return a copy of the contents
      if (packet_type == TMID || packet_type == STMID) {
        packet = std::tr1::shared_ptr<TmidPacket>(new TmidPacket(
            *std::tr1::static_pointer_cast<TmidPacket>(retrieved_packet)));
      } else if (packet_type == MID || packet_type == SMID) {
        packet = std::tr1::shared_ptr<MidPacket>(new MidPacket(
            *std::tr1::static_pointer_cast<MidPacket>(retrieved_packet)));
      } else if (IsSignature(packet_type, false)) {
        packet = std::tr1::shared_ptr<SignaturePacket>(new SignaturePacket(
            *std::tr1::static_pointer_cast<SignaturePacket>(retrieved_packet)));
      } else {
#ifdef DEBUG
        printf("SystemPacketHandler::Packet: %s type error.\n",
                DebugString(packet_type).c_str());
#endif
      }
    } else {
#ifdef DEBUG
      printf("SystemPacketHandler::Packet: %s not ",
             DebugString(packet_type).c_str());
      printf(confirmed ? "confirmed as stored.\n" : "pending confirmation.\n");
#endif
    }
  }
  return packet;
}

bool SystemPacketHandler::Confirmed(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  return IsConfirmed(packets_.find(packet_type));
}

bool SystemPacketHandler::IsConfirmed(SystemPacketMap::iterator it) {
  return (it != packets_.end() && !(*it).second.pending.get() &&
          (*it).second.stored.get());
}

std::string SystemPacketHandler::SerialiseKeyring() {
  Keyring keyring;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.begin();
  while (it != packets_.end()) {
    if (IsSignature((*it).first, false) && (*it).second.stored.get()) {
      std::tr1::static_pointer_cast<SignaturePacket>((*it).second.stored)->
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
    std::tr1::shared_ptr<SignaturePacket> sig_packet(
        new SignaturePacket(keyring.key(i)));
    PacketInfo packet_info;
    packet_info.stored = sig_packet;
    std::pair<SystemPacketMap::iterator, bool> result =
        packets_.insert(SystemPacketMap::value_type(
            static_cast<PacketType>(sig_packet->packet_type()), packet_info));
#ifdef DEBUG
    if (!result.second)
      printf("SystemPacketHandler::ParseKeyring: Failed for %s.\n",
              DebugString(sig_packet->packet_type()).c_str());
#endif
    success = success && result.second;
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

void SystemPacketHandler::Clear() {
  boost::mutex::scoped_lock lock(mutex_);
  packets_.clear();
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
