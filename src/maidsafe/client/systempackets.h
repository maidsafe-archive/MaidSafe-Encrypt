/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Classes of system packets
* Version:      1.0
* Created:      2009-01-29-00.59.58
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

#ifndef MAIDSAFE_CLIENT_SYSTEMPACKETS_H_
#define MAIDSAFE_CLIENT_SYSTEMPACKETS_H_

#include <string>

#include "protobuf/packet.pb.h"
#include "maidsafe/client/packetfactory.h"

namespace maidsafe {

class SignaturePacket : public Packet {
 public:
  PacketParams Create(PacketParams params);
};
class MidPacket : public Packet {
 public:
  PacketParams GetData(std::string serialised_packet,
                     std::string username,
                     std::string PIN);
  PacketParams Create(PacketParams params);
  std::string PacketName(PacketParams params);
};

class SmidPacket : public MidPacket {
 public:
  PacketParams Create(PacketParams params);
  std::string PacketName(PacketParams params);
};

class TmidPacket : public Packet {
 public:
  PacketParams Create(PacketParams params);
  PacketParams GetData(std::string serialised_packet,
                     std::string password,
                     uint32_t rid);
  std::string PacketName(PacketParams params);
};
class PmidPacket : public Packet {
 public:
  PacketParams Create(PacketParams params);
};
class MpidPacket : public Packet {
 public:
  PacketParams Create(PacketParams params);
  std::string PacketName(PacketParams params);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_SYSTEMPACKETS_H_

