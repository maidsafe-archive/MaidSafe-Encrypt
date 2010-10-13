/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Setters and getters for system signature packets
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

#include "maidsafe/passport/systempackets.h"
//#include <boost/lexical_cast.hpp>
//#include <maidsafe/base/utils.h>

namespace maidsafe {

namespace passport {

SignaturePacket::SignaturePacket(const PacketType &packet_type,
                                 const std::string &public_key,
                                 const std::string &private_key,
                                 const std::string &signer_private_key)
    : pki::Packet(),
      public_key_(public_key),
      private_key_(private_key),
      signer_private_key_(signer_private_key),
      signature_() {
  Initialise();
}

void SignaturePacket::Initialise() {
  if (public_key_.empty() || private_key_.empty())
    return Clear();

  if (signer_private_key_.empty())  // this is a self-signing packet
    signer_private_key_ = private_key_;

  try {
    signature_ = crypto_obj_.AsymSign(public_key_, "", signer_private_key_,
                                      crypto::STRING_STRING);
    name_ = crypto_obj_.Hash(public_key_ + signature_, "",
                             crypto::STRING_STRING, false);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MidPacket::Initialise: %s\n", e.what());
#endif
    name_.clear();
  }
  if (name_.empty())
    Clear();
}

void SignaturePacket::Clear() {
  name_.clear();
  public_key_.clear();
  private_key_.clear();
  signer_private_key_.clear();
  signature_.clear();
}



MidPacket::MidPacket(const std::string &username,
                     const std::string &pin,
                     const std::string &smid_appendix)
    : pki::Packet(),
      username_(username),
      pin_(pin),
      smid_appendix_(smid_appendix),
      encrypted_rid_(),
      salt_(),
      secure_password_(),
      rid_(0) {
  Initialise();
}

void MidPacket::Initialise() {
  if (username_.empty() || pin_.empty())
    return Clear();

  rid_ = base::RandomUint32();
  while (rid_ == 0)
    rid_ = base::RandomUint32();
  salt_ = crypto_obj_.Hash(pin_ + username_, "",
                           crypto::STRING_STRING, false);
  try {
    secure_password_ = crypto_obj_.SecurePassword(username_, salt_,
                       boost::lexical_cast<boost::uint32_t>(pin_));
    name_ = crypto_obj_.Hash(
                crypto_obj_.Hash(username_, "", crypto::STRING_STRING, false) +
                crypto_obj_.Hash(pin_, "", crypto::STRING_STRING, false) +
                smid_appendix_, "", crypto::STRING_STRING, false);
    encrypted_rid_ =
        crypto_obj_.SymmEncrypt(boost::lexical_cast<std::string>(rid_), "",
                                crypto::STRING_STRING, secure_password_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MidPacket::Initialise: %s\n", e.what());
#endif
    encrypted_rid_.clear();
  }
  if (encrypted_rid_.empty())
    Clear();
}

boost::uint32_t MidPacket::ParseRid(const std::string &serialised_mid_packet) {
  GenericPacket packet;
  if (username_.empty() || pin_.empty() ||
      !packet.ParseFromString(serialised_mid_packet))
    return 0;

  try {
    encrypted_rid_ = packet.data();
    std::string rid(crypto_obj_.SymmDecrypt(encrypted_rid_, "",
                    crypto::STRING_STRING, secure_password_));
    rid_ = boost::lexical_cast<boost::uint32_t>(rid);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MidPacket::ParseRid: %s\n", e.what());
#endif
    rid_ = 0;
  }
  if (rid_ == 0)
    Clear();
  return rid_;
}

void MidPacket::Clear() {
  name_.clear();
  username_.clear();
  pin_.clear();
  smid_appendix_.clear();
  encrypted_rid_.clear();
  salt_.clear();
  secure_password_.clear();
  rid_ = 0;
}



TmidPacket::TmidPacket(const std::string &username,
                       const std::string &pin,
                       const std::string &password,
                       const boost::uint32_t rid,
                       const std::string &plain_data)
    : pki::Packet(),
      username_(username),
      pin_(pin),
      password_(password),
      rid_(rid),
      plain_data_(plain_data),
      salt_(),
      secure_password_(),
      encrypted_data_() {
  Initialise();
}

void TmidPacket::Initialise() {
  if (username_.empty() || pin_.empty() || password_.empty() || rid_ == 0)
    return Clear();

  try {
    salt_ = crypto_obj_.Hash(boost::lexical_cast<std::string>(rid_) + password_,
                             "", crypto::STRING_STRING, false);
    secure_password_ = crypto_obj_.SecurePassword(password_, salt_, rid_);
    if (plain_data_.empty())  // Only initialising in order to parse plain data;
      return;                 // don't need name or enc data.
    name_ = crypto_obj_.Hash(
                crypto_obj_.Hash(username_, "", crypto::STRING_STRING, false) +
                crypto_obj_.Hash(pin_, "", crypto::STRING_STRING, false) +
                crypto_obj_.Hash(boost::lexical_cast<std::string>(rid_), "",
                                 crypto::STRING_STRING, false), "",
                crypto::STRING_STRING, false);
    encrypted_data_ = crypto_obj_.SymmEncrypt(plain_data_, "",
                      crypto::STRING_STRING, secure_password_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("TmidPacket::Initialise: %s\n", e.what());
#endif
    encrypted_data_.clear();
  }
  if (encrypted_data_.empty())
    Clear();
}

std::string TmidPacket::ParsePlainData(
    const std::string &serialised_tmid_packet) {
  GenericPacket packet;
  if (secure_password_.empty() ||
      !packet.ParseFromString(serialised_tmid_packet))
    return 0;

  try {
    encrypted_data_ = packet.data();
    plain_data_ = crypto_obj_.SymmDecrypt(encrypted_data_, "",
                  crypto::STRING_STRING, secure_password_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("TmidPacket::ParsePlainData: %s\n", e.what());
#endif
    plain_data_.clear();
  }
  if (plain_data_.empty())
    Clear();
  return plain_data_;
}

void TmidPacket::Clear() {
  name_.clear();
  username_.clear();
  pin_.clear();
  password_.clear();
  rid_ = 0;
  plain_data_.clear();
  salt_.clear();
  secure_password_.clear();
  encrypted_data_.clear();
}



MpidPacket::MpidPacket(const std::string &public_name,
                       const std::string &public_key,
                       const std::string &private_key)
    : pki::Packet(),
      public_name_(public_name),
      public_key_(public_key),
      private_key_(private_key) {
  Initialise();
}

void MpidPacket::Initialise() {
  if (public_name_.empty() || public_key_.empty() || private_key_.empty())
    return Clear();

  try {
    name_ = crypto_obj_.Hash(public_name_, "", crypto::STRING_STRING, false);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MpidPacket::Initialise: %s\n", e.what());
#endif
    name_.clear();
  }
  if (name_.empty())
    Clear();
}

std::string MpidPacket::ParsePublicKey(
    const std::string &serialised_mpid_packet) {
  GenericPacket packet;
  if (!packet.ParseFromString(serialised_mpid_packet))
    return "";
  else
    return packet.data();
}

void MpidPacket::Clear() {
  name_.clear();
  public_name_.clear();
  public_key_.clear();
  private_key_.clear();
}

}  // namespace passport

}  // namespace maidsafe
