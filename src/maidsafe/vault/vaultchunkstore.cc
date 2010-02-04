/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose
 */

#include "maidsafe/vault/vaultchunkstore.h"

#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_array.hpp>
#include <boost/thread/mutex.hpp>

#include <set>

namespace maidsafe_vault {

int VaultChunkStore::UpdateChunk(const std::string &key,
                                 const std::string &value) {
  int valid = InitialOperationVerification(key);
  if (valid != kSuccess)
    return valid;

  // check we have the chunk already
  maidsafe::ChunkType type = kInvalidChunkType;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<maidsafe::non_hex_name>().find(key);
    if (itr != chunkstore_set_.end())
      type = (*itr).type_;
  }
  if (type == kInvalidChunkType) {
#ifdef DEBUG
    printf("In ChunkStore::UpdateChunk, don't currently have chunk.\n");
#endif
    return kInvalidChunkType;
  }
  fs::path chunk_path(GetChunkPath(key, type, false));
  if (DeleteChunkFunction(key, chunk_path) != kSuccess)
    return kChunkstoreUpdateFailure;
  return (StoreChunkFunction(key, value, chunk_path, type) == kSuccess) ?
      kSuccess : kChunkstoreUpdateFailure;
}

maidsafe::ChunkInfo VaultChunkStore::GetOldestChecked() {
  maidsafe::ChunkInfo chunk;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_last_checked::iterator itr =
        chunkstore_set_.get<1>().begin();
    chunk = *itr;
  }
  return chunk;
}

int VaultChunkStore::LoadRandomChunk(std::string *key, std::string *value) {
  key->clear();
  value->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::LoadRandomChunk.\n");
#endif
    return kChunkstoreUninitialised;
  }
  bool result(false);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    if (chunkstore_set_.size() != 0)
      result = true;
  }
  if (!result) {
#ifdef DEBUG
    printf("In ChunkStore::LoadRandomChunk: there are no chunks stored.\n");
#endif
    return kChunkstoreError;
  }
  maidsafe::ChunkType type = (maidsafe::kHashable | maidsafe::kNormal);
  boost::uint64_t hashable_count(0);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_chunk_type &sorted_index =
        chunkstore_set_.get<maidsafe::chunk_type>();
    hashable_count = sorted_index.count(type);
  }
  if (!hashable_count)  // i.e. there are no chunks available
    return kChunkstoreError;
  int randindex = static_cast<int>(base::random_32bit_uinteger()
      % hashable_count);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_chunk_type::iterator itr =
         chunkstore_set_.get<maidsafe::chunk_type>().begin();
    for (int i = 0; i < randindex; ++i, ++itr) {}
    *key = (*itr).non_hex_name_;
    // check we've got the correct type
    result = ((*itr).type_ == type);
  }
  if (result)
    return Load(*key, value);
  else
    return kChunkstoreError;
}

void VaultChunkStore::GetAllChunks(std::list<std::string> *chunk_names) {
  chunk_names->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::GetAllChunks.\n");
#endif
    return;
  }
  boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
  for (maidsafe::chunk_set_by_non_hex_name::iterator itr =
       chunkstore_set_.get<maidsafe::non_hex_name>().begin();
       itr != chunkstore_set_.get<maidsafe::non_hex_name>().end(); ++itr) {
    chunk_names->push_back((*itr).non_hex_name_);
  }
}

int VaultChunkStore::HashCheckAllChunks(bool delete_failures,
                                        std::list<std::string> *failed_keys) {
  failed_keys->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::HashCheckAllChunks.\n");
#endif
    return kChunkstoreUninitialised;
  }
  boost::uint64_t filecount;
  bool result(true);
  for (maidsafe::path_map_iterator path_map_itr = path_map_.begin();
       path_map_itr != path_map_.end(); ++path_map_itr) {
    maidsafe::ChunkType type = path_map_itr->first;
    if (type & maidsafe::kHashable) {
      FindFiles(path_map_itr->second, type, true, delete_failures, &filecount,
                failed_keys);
    }
  }
  if (delete_failures) {
    std::list<std::string>::iterator itr;
    for (itr = failed_keys->begin(); itr != failed_keys->end(); ++itr) {
      if (DeleteChunk((*itr)) == kSuccess) {
        --filecount;
      } else {
        result = false;
      }
    }
  }
  return result ? kSuccess : kHashCheckFailure;
}

int VaultChunkStore::CacheChunk(const std::string &key,
                                const std::string &value) {
  if (Has(key))
    return kSuccess;

  if (!EnoughSpace(value.size()))
    return kNoSpaceForCaching;

  maidsafe::ChunkType ct(maidsafe::kHashable | maidsafe::kCache);
  fs::path store_path = GetChunkPath(key, ct, true);
  int n = StoreChunkFunction(key, value, store_path, ct);
  if (n != kSuccess)
    return n;

  space_used_by_cache_ += value.size();
  return kSuccess;
}

int VaultChunkStore::FreeCacheSpace(const boost::uint64_t &space_to_clear) {
  if (space_used_by_cache() == 0)
    return kNoCacheSpaceToClear;

  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::ChunkInfo chunk;
    boost::uint64_t cleared_so_far(0);
    while (cleared_so_far < space_to_clear) {
      maidsafe::chunk_set_by_last_checked::iterator itr =
          chunkstore_set_.get<1>().begin();
      chunk = *itr;
      if (chunk.type_ & maidsafe::kCache) {
        fs::path p(GetChunkPath(chunk.non_hex_name_, chunk.type_, false));
        try {
          fs::remove_all(p);
        }
        catch(const std::exception &e) {}
        maidsafe::chunk_set_by_non_hex_name::iterator name_itr =
            chunkstore_set_.get<0>().find(chunk.non_hex_name_);
        chunkstore_set_.erase(name_itr);
        space_used_by_cache_ -= chunk.size_;
        cleared_so_far += chunk.size_;
      }
    }
  }
  return kSuccess;
}

int VaultChunkStore::StorePacket(const std::string &packet_name,
                                 const maidsafe::GenericPacket &gp) {
  int valid = InitialOperationVerification(packet_name);
  if (valid != kSuccess)
    return valid;

  boost::mutex::scoped_lock loch(packetstore_set_mutex_);
  typedef packet_store_set::index<store_packet_unique_key>::type
          store_packet_by_unique_key;
  store_packet_by_unique_key& packet_store_projection =
      pss_.get<store_packet_unique_key>();
  store_packet_by_unique_key::iterator it = packet_store_projection.find(
      boost::make_tuple(packet_name, gp.data()));
  if (it != packet_store_projection.end())
    return kPacketStoreValueExists;

  PacketStoreRow psr(packet_name, gp.data(), gp.signature(), 1);
  std::pair<packet_store_set::iterator, bool> result = pss_.insert(psr);

  return result.second ? kSuccess : kPacketStoreFailure;
}

int VaultChunkStore::AppendToPacket(const std::string &packet_name,
                                    const maidsafe::GenericPacket &gp,
                                    const std::string &public_key) {
  int valid = InitialOperationVerification(packet_name);
  if (valid != kSuccess)
    return valid;

  boost::mutex::scoped_lock loch(packetstore_set_mutex_);
  typedef packet_store_set::index<store_packet_unique_key>::type
          store_packet_by_unique_key;
  typedef packet_store_set::index<store_packet_index>::type
          store_packet_by_index;
  store_packet_by_unique_key& unique_key_index =
      pss_.get<store_packet_unique_key>();
  store_packet_by_index& index_index = pss_.get<store_packet_index>();
  store_packet_by_unique_key::iterator uk_it = unique_key_index.find(
      boost::make_tuple(packet_name, gp.data()));
  if (uk_it != unique_key_index.end())
    return kPacketAppendValueExists;
  store_packet_by_index::iterator i_it = index_index.find(
      boost::make_tuple(packet_name));
  if (i_it == index_index.end())
    return kPacketAppendNotFound;

  std::string data = (*i_it).data_;
  std::string signature = (*i_it).signature_;
  crypto::Crypto co;
  if (!co.AsymCheckSig(data, signature, public_key, crypto::STRING_STRING))
    return kPacketAppendNotOwned;

  int next_id = (*i_it).index_ + 1;
  PacketStoreRow psr(packet_name, gp.data(), gp.signature(), next_id);
  std::pair<packet_store_set::iterator, bool> result = pss_.insert(psr);

  return result.second ? kSuccess : kPacketAppendFailure;
}

int VaultChunkStore::OverwritePacket(
    const std::string &packet_name,
    const std::vector<maidsafe::GenericPacket> &gps,
    const std::string &public_key) {
  int valid = InitialOperationVerification(packet_name);
  if (valid != kSuccess)
    return valid;

  boost::mutex::scoped_lock loch(packetstore_set_mutex_);
  typedef packet_store_set::index<store_packet_unique_key>::type
          store_packet_by_unique_key;
  std::pair<packet_store_set::iterator, packet_store_set::iterator> p;
  p = pss_.equal_range(boost::make_tuple(packet_name));
  if (p.first == p.second)
    return kPacketOverwriteNotFound;

  packet_store_set::iterator it = p.first;
  std::string data = (*it).data_;
  std::string signature = (*it).signature_;
  crypto::Crypto co;
  if (!co.AsymCheckSig(data, signature, public_key, crypto::STRING_STRING))
    return kPacketOverwriteNotOwned;

  while (it != p.second)
    it = pss_.erase(it);

  bool inserts = true;
  std::set<std::string> data_set;
  for (size_t n = 0; n < gps.size(); ++n) {
    std::pair<std::set<std::string>::iterator, bool> p;
    p = data_set.insert(gps[n].data());
    if (!p.second)
      continue;
    PacketStoreRow psr(packet_name, gps[n].data(), gps[n].signature(),
                       gps.size() - (n + 1));
    std::pair<packet_store_set::iterator, bool> result = pss_.insert(psr);
    if (!result.second) {
      inserts = false;
      break;
    }
  }

  if (!inserts) {
    p = pss_.equal_range(boost::make_tuple(packet_name));
    store_packet_by_unique_key::iterator it = p.first;
    while (it != p.second)
      it = pss_.erase(it);
  }

  return inserts ? kSuccess : kPacketOverwriteFailure;
}

int VaultChunkStore::DeletePacket(
    const std::string &packet_name,
    const std::vector<maidsafe::GenericPacket> &gps,
    const std::string &public_key) {
  int valid = InitialOperationVerification(packet_name);
  if (valid != kSuccess)
    return valid;

  boost::mutex::scoped_lock loch(packetstore_set_mutex_);
  typedef packet_store_set::index<store_packet_unique_key>::type
          store_packet_by_unique_key;
  store_packet_by_unique_key& packet_store_projection =
      pss_.get<store_packet_unique_key>();
  store_packet_by_unique_key::iterator it = packet_store_projection.find(
      boost::make_tuple(packet_name));
  if (it == packet_store_projection.end())
    return kPacketDeleteNotFound;

  std::string data = (*it).data_;
  std::string signature = (*it).signature_;
  crypto::Crypto co;
  if (!co.AsymCheckSig(data, signature, public_key, crypto::STRING_STRING))
    return kPacketDeleteNotOwned;

  if (gps.size() == 0) {
    std::pair<store_packet_by_unique_key::iterator,
              store_packet_by_unique_key::iterator> p;
    p = pss_.equal_range(boost::make_tuple(packet_name));
    while (it != p.second) {
      it = pss_.erase(it);
    }
  } else {
    for (size_t n = 0; n < gps.size(); ++n) {
      it = packet_store_projection.find(boost::make_tuple(packet_name,
           gps[n].data()));
      if (it != packet_store_projection.end())
        pss_.erase(it);
    }
  }
  return kSuccess;
}

int VaultChunkStore::LoadPacket(const std::string &packet_name,
                                std::vector<maidsafe::GenericPacket> *gps) {
  gps->clear();
  int valid = InitialOperationVerification(packet_name);
  if (valid != kSuccess)
    return valid;

  boost::mutex::scoped_lock loch(packetstore_set_mutex_);
  typedef packet_store_set::index<store_packet_index>::type
          store_packet_by_index;
  store_packet_by_index& index_index = pss_.get<store_packet_index>();
  store_packet_by_index::iterator i_it = index_index.find(
      boost::make_tuple(packet_name));
  if (i_it == index_index.end())
    return kPacketLoadNotFound;

  while (i_it != index_index.end() && (*i_it).packet_name_ == packet_name) {
    maidsafe::GenericPacket gp;
    gp.set_data((*i_it).data_);
    gp.set_signature((*i_it).signature_);
    gps->push_back(gp);
    ++i_it;
  }
  return kSuccess;
}

bool VaultChunkStore::HasPacket(const std::string &packet_name) {
  int valid = InitialOperationVerification(packet_name);
  if (valid != kSuccess)
    return false;
  boost::mutex::scoped_lock loch(packetstore_set_mutex_);
  typedef packet_store_set::index<store_packet_index>::type
          store_packet_by_index;
  store_packet_by_index& index_index = pss_.get<store_packet_index>();
  store_packet_by_index::iterator i_it = index_index.find(
      boost::make_tuple(packet_name));
  return i_it != index_index.end();
}

bool VaultChunkStore::EnoughSpace(const boost::uint64_t &length) {
  if (FreeSpace() < length)
    return false;
  return true;
}

}  // namespace maidsafe_vault
