/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Created:      2010-04-08
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

#include "maidsafe/vault/bufferpacketstore.h"

namespace maidsafe {

namespace vault {

bool BufferPacketStore::StoreBP(const std::string &name,
                                const std::string &ser_bp) {
  boost::mutex::scoped_lock lock(bp_store_mutex_);
  if (buffer_packets_.count(name) == 1)
    return false;
  buffer_packets_[name] = ser_bp;
  return true;
}

bool BufferPacketStore::LoadBP(const std::string &name, std::string *ser_bp) {
  boost::mutex::scoped_lock lock(bp_store_mutex_);
  if (buffer_packets_.count(name) != 1)
    return false;
  *ser_bp = buffer_packets_[name];
  return true;
}

bool BufferPacketStore::UpdateBP(const std::string &name,
                                 const std::string &ser_bp) {
  boost::mutex::scoped_lock lock(bp_store_mutex_);
  if (buffer_packets_.count(name) != 1)
    return false;
  buffer_packets_[name] = ser_bp;
  return true;
}

bool BufferPacketStore::DeleteBP(const std::string &name) {
  boost::mutex::scoped_lock lock(bp_store_mutex_);
  return buffer_packets_.erase(name) == 1;
}

bool BufferPacketStore::HasBP(const std::string &name) {
  boost::mutex::scoped_lock lock(bp_store_mutex_);
  return buffer_packets_.count(name) == 1;
}

void BufferPacketStore::ImportMapFromPb(
    const VaultBufferPacketMap &vault_bp_map) {
  for (int i = 0; i < vault_bp_map.vault_buffer_packet_size(); ++i) {
    InsertBufferPacketFromPb(vault_bp_map.vault_buffer_packet(i));
  }
}

VaultBufferPacketMap BufferPacketStore::ExportMapToPb() {
  VaultBufferPacketMap vault_bp_map;
  for (std::map<std::string, std::string>::iterator it =
           buffer_packets_.begin();
       it != buffer_packets_.end();
       ++it) {
    VaultBufferPacketMap::VaultBufferPacket *vbp =
        vault_bp_map.add_vault_buffer_packet();
    vbp->set_bufferpacket_name(it->first);
    BufferPacket bp;
    bp.ParseFromString(it->second);
    for (int i = 0; i < bp.owner_info_size(); ++i) {
      GenericPacket *gp = vbp->add_owner_info();
      gp->set_data(bp.owner_info(i).data());
      gp->set_signature(bp.owner_info(i).signature());
    }
  }
  return vault_bp_map;
}

bool BufferPacketStore::InsertBufferPacketFromPb(
    const VaultBufferPacketMap::VaultBufferPacket &vault_bp) {
  BufferPacket bp;
  for (int i = 0; i < vault_bp.owner_info_size(); ++i) {
    GenericPacket *gp = bp.add_owner_info();
    gp->set_data(vault_bp.owner_info(i).data());
    gp->set_signature(vault_bp.owner_info(i).signature());
  }
  return StoreBP(vault_bp.bufferpacket_name(), bp.SerializeAsString());
}

}  // namespace vault

}  // namespace maidsafe
