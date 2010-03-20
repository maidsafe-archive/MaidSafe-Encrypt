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

#include "maidsafe/client/systempackets.h"
#include <boost/lexical_cast.hpp>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>
#include <cstdlib>
#include <ctime>
#include <cstdio>

namespace maidsafe {

PacketParams SignaturePacket::Create(PacketParams *params) {
  GenericPacket sig_packet;
  (*params)["privateKey"] = rsakp_.private_key();
  (*params)["publicKey"] = rsakp_.public_key();
  sig_packet.set_data(rsakp_.public_key());
  sig_packet.set_signature(crypto_obj_.AsymSign(rsakp_.public_key(), "",
                           rsakp_.private_key(), crypto::STRING_STRING));
  (*params)["name"] = crypto_obj_.Hash(sig_packet.data() +
                      sig_packet.signature(), "", crypto::STRING_STRING, false);
  std::string ser_packet;
  sig_packet.SerializeToString(&ser_packet);
  (*params)["ser_packet"] = ser_packet;
  return (*params);
}

PacketParams MidPacket::Create(PacketParams *params) {
  GenericPacket mid_packet;
  PacketParams result;
  if (boost::any_cast<std::string>((*params)["username"]).empty() ||
      boost::any_cast<std::string>((*params)["PIN"]).empty() ||
      boost::any_cast<std::string>((*params)["privateKey"]).empty())
    return result;

  boost::uint32_t rid = base::random_32bit_uinteger();
  while (rid == 0)
    rid = base::random_32bit_uinteger();
  boost::uint32_t pin = boost::lexical_cast<boost::uint32_t>(boost::any_cast
    <std::string>((*params)["PIN"]));
  std::string password = crypto_obj_.SecurePassword(
                         boost::any_cast<std::string>((*params)["username"]),
                         pin);
  mid_packet.set_data(crypto_obj_.SymmEncrypt(boost::lexical_cast<std::string>
    (rid), "", crypto::STRING_STRING, password));
  mid_packet.set_signature(crypto_obj_.AsymSign(mid_packet.data(), "",
                           boost::any_cast<std::string>(
                           (*params)["privateKey"]), crypto::STRING_STRING));

  if (mid_packet.signature().empty())
    return result;

  result["name"] = PacketName(params);
  result["rid"] = rid;
  result["encRid"] = mid_packet.data();
  std::string ser_packet;
  mid_packet.SerializeToString(&ser_packet);
  result["ser_packet"] = ser_packet;
  return result;
}

PacketParams MidPacket::GetData(const std::string &serialised_packet,
                                const std::string &username,
                                const std::string &PIN) {
  GenericPacket mid_packet;
  PacketParams result;
  if (serialised_packet.empty()) {
    result["data"] = boost::uint32_t(0);
    return result;
  }
  if (!mid_packet.ParseFromString(serialised_packet)) {
    result["data"] = boost::uint32_t(0);
  } else {
    boost::uint16_t pin = boost::lexical_cast<boost::uint16_t>(PIN);
    std::string password = crypto_obj_.SecurePassword(username, pin);
    std::string str_rid = crypto_obj_.SymmDecrypt(mid_packet.data(), "",
                          crypto::STRING_STRING, password);
    try {
      result["data"] = boost::lexical_cast<boost::uint32_t>(str_rid);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In MidPacket::GetData - %s\n", e.what());
#endif
      result["data"] = boost::uint32_t(0);
    }
  }
  return result;
}

std::string MidPacket::PacketName(PacketParams *params) {
  return crypto_obj_.Hash(
         crypto_obj_.Hash(boost::any_cast<std::string>((*params)["username"]),
                          "", crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::any_cast<std::string>((*params)["PIN"]),
                          "", crypto::STRING_STRING, false), "",
         crypto::STRING_STRING, false);
}

PacketParams SmidPacket::Create(PacketParams *params) {
  GenericPacket smid_packet;
  PacketParams result;
  if (boost::any_cast<std::string>((*params)["username"]).empty() ||
      boost::any_cast<std::string>((*params)["PIN"]).empty() ||
      boost::any_cast<std::string>((*params)["privateKey"]).empty())
    return result;
  boost::uint32_t pin = boost::lexical_cast<boost::uint32_t>
    (boost::any_cast<std::string>((*params)["PIN"]));
  std::string password = crypto_obj_.SecurePassword(
                         boost::any_cast<std::string>((*params)["username"]),
                         pin);
  smid_packet.set_data(crypto_obj_.SymmEncrypt(boost::lexical_cast<std::string>(
                       boost::any_cast<boost::uint32_t>((*params)["rid"])), "",
                       crypto::STRING_STRING, password));
  smid_packet.set_signature(crypto_obj_.AsymSign(smid_packet.data(), "",
                            boost::any_cast<std::string>(
                            (*params)["privateKey"]), crypto::STRING_STRING));

  if (smid_packet.signature().empty())
    return result;

  std::string ser_packet;
  result["name"] = PacketName(params);
  result["encRid"] = smid_packet.data();
  smid_packet.SerializeToString(&ser_packet);
  result["ser_packet"] = ser_packet;
  return result;
}

std::string SmidPacket::PacketName(PacketParams *params) {
  // TODO(Team#5#): Change the +1 to some other means of randomness
  return crypto_obj_.Hash(
         crypto_obj_.Hash(boost::any_cast<std::string>((*params)["username"]),
                          "", crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::any_cast<std::string>((*params)["PIN"]), "",
                          crypto::STRING_STRING, false) + "1", "",
         crypto::STRING_STRING, false);
}

PacketParams TmidPacket::Create(PacketParams *params) {
  GenericPacket tmid_packet;
  PacketParams result;
  if (boost::any_cast<std::string>((*params)["username"]).empty() ||
      boost::any_cast<std::string>((*params)["password"]).empty() ||
      boost::any_cast<std::string>((*params)["PIN"]).empty() ||
      boost::any_cast<std::string>((*params)["data"]).empty() ||
      boost::any_cast<std::string>((*params)["privateKey"]).empty())
    return result;

  std::string password = crypto_obj_.SecurePassword(
                         boost::any_cast<std::string>((*params)["password"]),
                         boost::any_cast<boost::uint32_t>((*params)["rid"]));
#ifdef DEBUG
  // printf("password %s\n", params["password"].string().c_str());
  // printf("rid %i\n", params["rid"].integer());
#endif
  tmid_packet.set_data(crypto_obj_.SymmEncrypt(boost::any_cast<std::string>(
                       (*params)["data"]), "", crypto::STRING_STRING,
                       password));
  tmid_packet.set_signature(crypto_obj_.AsymSign(tmid_packet.data(), "",
                            boost::any_cast<std::string>(
                            (*params)["privateKey"]), crypto::STRING_STRING));

  if (tmid_packet.signature().empty()) {
#ifdef DEBUG
    printf("Failed signature.\n");
#endif
    return result;
  }

  result["name"] = PacketName(params);
  std::string ser_packet;
  tmid_packet.SerializeToString(&ser_packet);
  result["ser_packet"] = ser_packet;
  result["data"] = tmid_packet.data();
  return result;
}

PacketParams TmidPacket::GetData(const std::string &serialised_packet,
                                 const std::string &password,
                                 const boost::uint32_t &rid) {
  GenericPacket tmid_packet;
  PacketParams result;
  if (!tmid_packet.ParseFromString(serialised_packet)) {
    printf("Nalgaaaaaaaaaaaaaaaaaaaa\n");
    result["data"] = std::string();
  } else {
    std::string secure_passw = crypto_obj_.SecurePassword(password, rid);
    result["data"] = crypto_obj_.SymmDecrypt(tmid_packet.data(), "",
                     crypto::STRING_STRING, secure_passw);
  }
  return result;
}

std::string TmidPacket::PacketName(PacketParams *params) {
#ifdef DEBUG
  // printf("rid %i\n", params["rid"].integer());
#endif
  return crypto_obj_.Hash(
         crypto_obj_.Hash(boost::any_cast<std::string>((*params)["username"]),
                          "", crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::any_cast<std::string>((*params)["PIN"]), "",
                          crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::lexical_cast<std::string>
                          (boost::any_cast<boost::uint32_t>(
                          (*params)["rid"])), "", crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);
}

PacketParams PmidPacket::Create(PacketParams *params) {
  PacketParams result;
  if (boost::any_cast<std::string>((*params)["privateKey"]).empty())
    return result;
  GenericPacket pmid_packet;
  pmid_packet.set_data(rsakp_.public_key());
  pmid_packet.set_signature(crypto_obj_.AsymSign(rsakp_.public_key(), "",
                            boost::any_cast<std::string>(
                            (*params)["privateKey"]), crypto::STRING_STRING));
  if (pmid_packet.signature().empty())
    return result;
  result["privateKey"] = rsakp_.private_key();
  result["publicKey"] = rsakp_.public_key();
  result["name"] = crypto_obj_.Hash(pmid_packet.data() +
                   pmid_packet.signature(), "", crypto::STRING_STRING, false);
  result["signature"] = pmid_packet.signature();

  std::string ser_packet;
  pmid_packet.SerializeToString(&ser_packet);
  result["ser_packet"] = ser_packet;
  return result;
}

PacketParams MpidPacket::Create(PacketParams *params) {
  PacketParams result;
  if (boost::any_cast<std::string>((*params)["publicname"]).empty() ||
      boost::any_cast<std::string>((*params)["privateKey"]).empty())
    return result;
  GenericPacket mpid_packet;
  mpid_packet.set_data(rsakp_.public_key());
  mpid_packet.set_signature(crypto_obj_.AsymSign(rsakp_.public_key(), "",
                            boost::any_cast<std::string>(
                            (*params)["privateKey"]), crypto::STRING_STRING));
  if (mpid_packet.signature().empty())
    return result;
  result["privateKey"] = rsakp_.private_key();
  result["publicKey"] = rsakp_.public_key();
  result["name"] = PacketName(params);
  std::string ser_packet;
  mpid_packet.SerializeToString(&ser_packet);
  result["ser_packet"] = ser_packet;
  return result;
}

std::string MpidPacket::PacketName(PacketParams *params) {
  return crypto_obj_.Hash(boost::any_cast<std::string>((*params)["publicname"]),
                          "", crypto::STRING_STRING, false);
}

}  // namespace maidsafe
