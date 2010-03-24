/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Factory for system signature packets
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

#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/systempackets.h"

namespace maidsafe {

Packet::Packet(const crypto::RsaKeyPair &rsakp) : crypto_obj_(), rsakp_(rsakp) {
  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
  crypto_obj_.set_symm_algorithm(crypto::AES_256);
  if (rsakp_.private_key().empty())
    rsakp_.GenerateKeys(kRsaKeySize);
}

PacketParams Packet::GetData(const std::string &serialised_packet) {
  PacketParams result;
  GenericPacket packet;
  if (!packet.ParseFromString(serialised_packet))
    result["data"] = std::string();
  else
    result["data"] = packet.data();
  return result;
}

bool Packet::ValidateSignature(const std::string &serialised_packet,
                               const std::string &public_key) {
  GenericPacket packet;
  if (!packet.ParseFromString(serialised_packet))
    return false;
  return crypto_obj_.AsymCheckSig(packet.data(), packet.signature(), public_key,
                                  crypto::STRING_STRING);
}

boost::shared_ptr<Packet> PacketFactory::Factory(
    PacketType type,
    const crypto::RsaKeyPair &rsakp) {
  switch (type) {
    case MID:
      return boost::shared_ptr<Packet>(new MidPacket(rsakp));
    case SMID:
      return boost::shared_ptr<Packet>(new SmidPacket(rsakp));
    case TMID:
      return boost::shared_ptr<Packet>(new TmidPacket(rsakp));
    case MPID:
      return boost::shared_ptr<Packet>(new MpidPacket(rsakp));
    case PMID:
      return boost::shared_ptr<Packet>(new PmidPacket(rsakp));
    default:
      return boost::shared_ptr<Packet>(new SignaturePacket(rsakp));
  }
}

}  // namespace maidsafe
