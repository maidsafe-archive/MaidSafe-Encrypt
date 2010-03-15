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

CryptoKeyPairs::CryptoKeyPairs()
    : max_thread_count_(0),
      buffer_count_(0),
      running_thread_count_(0),
      key_buffer_(),
      kb_mutex_(),
      kb_cond_var_(),
      threads_() {}

CryptoKeyPairs::~CryptoKeyPairs() {
  set_max_thread_count(0);
  while (running_thread_count_ > 0)
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
}

void CryptoKeyPairs::Init(const boost::uint16_t &max_thread_count,
                          const boost::uint16_t &buffer_count) {
  set_buffer_count(buffer_count);
  set_max_thread_count(max_thread_count);
}

void CryptoKeyPairs::CreateThread() {
  boost::mutex::scoped_lock lock(kb_mutex_);
  if ((running_thread_count_ < max_thread_count_) &&
      (key_buffer_.size() + running_thread_count_ < buffer_count_)) {
    boost::shared_ptr<boost::thread> thr(new boost::thread(
        &maidsafe::CryptoKeyPairs::CreateKeyPair, this));
    ++running_thread_count_;
  }
}

void CryptoKeyPairs::DestroyThread() {
  boost::mutex::scoped_lock lock(kb_mutex_);
  --running_thread_count_;
  kb_cond_var_.notify_one();
}

void CryptoKeyPairs::CreateKeyPair() {
  boost::this_thread::at_thread_exit(boost::bind(&CryptoKeyPairs::DestroyThread,
      this));
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(kRsaKeySize);
  {
    boost::mutex::scoped_lock lock(kb_mutex_);
    key_buffer_.push(rsakp);
    kb_cond_var_.notify_one();
  }
  CreateThread();
}

crypto::RsaKeyPair CryptoKeyPairs::GetKeyPair() {
  boost::mutex::scoped_lock lock(kb_mutex_);
  crypto::RsaKeyPair rsakp;
  if (running_thread_count_ > 0 && buffer_count_ > 0) {
    while (key_buffer_.empty() && running_thread_count_ > 0 &&
           buffer_count_ > 0) {
      kb_cond_var_.wait(lock);
    }
    if (!key_buffer_.empty()) {
      rsakp = key_buffer_.front();
      key_buffer_.pop();
    }
  }
  if (rsakp.public_key().empty() || rsakp.private_key().empty()) {
    rsakp.ClearKeys();
    rsakp.GenerateKeys(kRsaKeySize);
  }
  lock.unlock();
  CreateThread();
  return rsakp;
}

boost::uint16_t CryptoKeyPairs::max_thread_count() {
  boost::mutex::scoped_lock lock(kb_mutex_);
  return max_thread_count_;
}

boost::uint16_t CryptoKeyPairs::buffer_count() {
  boost::mutex::scoped_lock lock(kb_mutex_);
  return buffer_count_;
}

void CryptoKeyPairs::set_max_thread_count(
    const boost::uint16_t &max_thread_count) {
  {
    boost::mutex::scoped_lock lock(kb_mutex_);
    if (max_thread_count > kMaxCryptoThreadCount)
      max_thread_count_ = kMaxCryptoThreadCount;
    else
      max_thread_count_ = max_thread_count;
  }
  CreateThread();
}

void CryptoKeyPairs::set_buffer_count(const boost::uint16_t &buffer_count) {
  {
    boost::mutex::scoped_lock lock(kb_mutex_);
    if (buffer_count > kNoOfSystemPackets)
      buffer_count_ = kNoOfSystemPackets;
    else
      buffer_count_ = buffer_count;
    kb_cond_var_.notify_one();
  }
  CreateThread();
}

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
