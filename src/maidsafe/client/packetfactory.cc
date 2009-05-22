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

#include "maidsafe/client/systempackets.h"


namespace packethandler {

Packet::Packet(): crypto_obj_() {
  crypto_obj_.set_hash_algorithm("SHA512");
  crypto_obj_.set_symm_algorithm("AES_256");
}

bool Packet::ValidateSignature(const std::string &serialised_packet,
                               const std::string &public_key) {
  GenericPacket packet;
  if (!packet.ParseFromString(serialised_packet))
    return false;
  return crypto_obj_.AsymCheckSig(packet.data(),
                                  packet.signature(),
                                  public_key,
                                  maidsafe_crypto::STRING_STRING);
}

PacketParams Packet::GetData(std::string serialised_packet) {
  PacketParams result;
  GenericPacket packet;
  if (!packet.ParseFromString(serialised_packet))
    result["data"] = std::string("");
  else
    result["data"] = packet.data();
  return result;
}

Packet::~Packet() {}

Packet *PacketFactory::Factory(SystemPackets type) {
  switch (type) {
    case MID: return new MidPacket();break;
    case SMID: return new SmidPacket();break;
    case TMID: return new TmidPacket();break;
    case MPID: return new MpidPacket();break;
    case PMID: return new PmidPacket();break;
    default:return new SignaturePacket();
  }
}

}  // namespace packethandler
