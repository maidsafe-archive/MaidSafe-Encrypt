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

PacketParams SignaturePacket::Create(PacketParams params) {
  PacketParams result;
  if (boost::any_cast<std::string>(params["privateKey"]).empty() ||
      boost::any_cast<std::string>(params["publicKey"]).empty())
    return result;

  result["publicKey"] = boost::any_cast<std::string>(params["publicKey"]);
  result["privateKey"] = boost::any_cast<std::string>(params["privateKey"]);
  result["name"] = PacketName(params);

  return result;
}

PacketParams SignaturePacket::GetData(const std::string &ser_packet,
      PacketParams) {
  PacketParams result;
  GenericPacket packet;
  if (!packet.ParseFromString(ser_packet)) {
    result["data"] = std::string("");
  } else {
    result["data"] = packet.data();
  }
  return result;
}

std::string SignaturePacket::PacketName(PacketParams params) {
  if (boost::any_cast<std::string>(params["privateKey"]).empty() ||
      boost::any_cast<std::string>(params["publicKey"]).empty())
    return "";
  return crypto_obj_.Hash(boost::any_cast<std::string>(params["publicKey"]) +
      crypto_obj_.AsymSign(boost::any_cast<std::string>(params["publicKey"]),
        "", boost::any_cast<std::string>(params["privateKey"]),
        crypto::STRING_STRING),
      "", crypto::STRING_STRING, false);
}

PacketParams MidPacket::Create(PacketParams params) {
  PacketParams result;
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty())
    return result;

  boost::uint32_t rid = base::random_32bit_uinteger();
  while (rid == 0)
    rid = base::random_32bit_uinteger();
  boost::uint32_t pin = boost::lexical_cast<boost::uint32_t>(boost::any_cast
      <std::string>(params["pin"]));
  std::string password = crypto_obj_.SecurePassword(
      boost::any_cast<std::string>(params["username"]), pin);
  result["name"] = PacketName(params);
  result["encRid"] = crypto_obj_.SymmEncrypt(boost::lexical_cast<std::string>
      (rid), "", crypto::STRING_STRING, password);
  result["rid"] = rid;
  return result;
}

PacketParams MidPacket::GetData(const std::string &ser_packet,
      PacketParams params) {
  PacketParams result;
  GenericPacket packet;
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty() ||
      !packet.ParseFromString(ser_packet)) {
    result["data"] = boost::uint32_t(0);
  } else {
    boost::uint32_t pin = boost::lexical_cast<boost::uint32_t>(boost::any_cast
        <std::string>(params["pin"]));
    std::string password(crypto_obj_.SecurePassword(
        boost::any_cast<std::string>(params["username"]), pin));
    std::string str_rid(crypto_obj_.SymmDecrypt(packet.data(), "",
        crypto::STRING_STRING, password));
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

std::string MidPacket::PacketName(PacketParams params) {
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty())
    return "";
  return crypto_obj_.Hash(
         crypto_obj_.Hash(boost::any_cast<std::string>(params["username"]),
                          "", crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::any_cast<std::string>(params["pin"]),
                          "", crypto::STRING_STRING, false), "",
         crypto::STRING_STRING, false);
}

PacketParams SmidPacket::Create(PacketParams params) {
  PacketParams result;
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty())
    return result;
  boost::uint32_t pin = boost::lexical_cast<boost::uint32_t>
      (boost::any_cast<std::string>(params["pin"]));
  std::string password = crypto_obj_.SecurePassword(
      boost::any_cast<std::string>(params["username"]), pin);
  result["encRid"] = crypto_obj_.SymmEncrypt(boost::lexical_cast<std::string>(
      boost::any_cast<boost::uint32_t>(params["rid"])), "",
      crypto::STRING_STRING, password);

  result["name"] = PacketName(params);
  return result;
}

std::string SmidPacket::PacketName(PacketParams params) {
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty())
    return "";
  return crypto_obj_.Hash(
      crypto_obj_.Hash(boost::any_cast<std::string>(params["username"]), "",
          crypto::STRING_STRING, false) +
      crypto_obj_.Hash(boost::any_cast<std::string>(params["pin"]), "",
          crypto::STRING_STRING, false) +
      "1", "", crypto::STRING_STRING, false);
}

PacketParams TmidPacket::Create(PacketParams params) {
  GenericPacket tmid_packet;
  PacketParams result;
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["password"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty() ||
      boost::any_cast<std::string>(params["data"]).empty())
    return result;

  std::string password = crypto_obj_.SecurePassword(
      boost::any_cast<std::string>(params["password"]),
      boost::any_cast<boost::uint32_t>(params["rid"]));

  result["data"] = crypto_obj_.SymmEncrypt(boost::any_cast<std::string>(
      params["data"]), "", crypto::STRING_STRING, password);

  result["name"] = PacketName(params);
  return result;
}

PacketParams TmidPacket::GetData(const std::string &ser_packet,
      PacketParams params) {
  PacketParams result;
  GenericPacket packet;
  if (boost::any_cast<std::string>(params["password"]).empty() ||
      !packet.ParseFromString(ser_packet)) {
    result["data"] = std::string("");
  } else {
    std::string secure_passw = crypto_obj_.SecurePassword(
        boost::any_cast<std::string>(params["password"]),
        boost::any_cast<boost::uint32_t>(params["rid"]));
    result["data"] = crypto_obj_.SymmDecrypt(packet.data(), "",
        crypto::STRING_STRING, secure_passw);
  }
  return result;
}

std::string TmidPacket::PacketName(PacketParams params) {
  if (boost::any_cast<std::string>(params["username"]).empty() ||
      boost::any_cast<std::string>(params["pin"]).empty())
    return "";
  return crypto_obj_.Hash(
         crypto_obj_.Hash(boost::any_cast<std::string>(params["username"]), "",
                          crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::any_cast<std::string>(params["pin"]), "",
                          crypto::STRING_STRING, false) +
         crypto_obj_.Hash(boost::lexical_cast<std::string>
                          (boost::any_cast<boost::uint32_t>(
                          params["rid"])), "", crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);
}

PacketParams PmidPacket::Create(PacketParams params) {
  PacketParams result;
  if (boost::any_cast<std::string>(params["privateKey"]).empty() ||
      boost::any_cast<std::string>(params["publicKey"]).empty() ||
      boost::any_cast<std::string>(params["signerPrivateKey"]).empty())
    return result;

  result["privateKey"] = boost::any_cast<std::string>(params["privateKey"]);
  result["publicKey"] = boost::any_cast<std::string>(params["publicKey"]);
  result["signature"] = crypto_obj_.AsymSign(
      boost::any_cast<std::string>(params["publicKey"]), "",
      boost::any_cast<std::string>(params["signerPrivateKey"]),
      crypto::STRING_STRING);

  result["name"] = PacketName(params);

  return result;
}

std::string PmidPacket::PacketName(PacketParams params) {
  if (boost::any_cast<std::string>(params["publicKey"]).empty() ||
      boost::any_cast<std::string>(params["signerPrivateKey"]).empty())
    return "";
  std::string sig_pubkey(crypto_obj_.AsymSign(
      boost::any_cast<std::string>(params["publicKey"]), "",
      boost::any_cast<std::string>(params["signerPrivateKey"]),
      crypto::STRING_STRING));
  return crypto_obj_.Hash(
      boost::any_cast<std::string>(params["publicKey"]) + sig_pubkey, "",
      crypto::STRING_STRING, false);
}

PacketParams PmidPacket::GetData(const std::string &ser_packet,
      PacketParams) {
  PacketParams result;
  GenericPacket packet;
  if (!packet.ParseFromString(ser_packet)) {
    result["data"] = std::string("");
  } else {
    result["data"] = packet.data();
  }
  return result;
}

PacketParams MpidPacket::Create(PacketParams params) {
  PacketParams result;
  if (boost::any_cast<std::string>(params["publicname"]).empty() ||
      boost::any_cast<std::string>(params["publicKey"]).empty() ||
      boost::any_cast<std::string>(params["privateKey"]).empty())
    return result;
  result["publicKey"] = boost::any_cast<std::string>(params["publicKey"]);
  result["privateKey"] = boost::any_cast<std::string>(params["privateKey"]);
  result["name"] = PacketName(params);
  return result;
}

std::string MpidPacket::PacketName(PacketParams params) {
  if (boost::any_cast<std::string>(params["publicname"]).empty())
    return "";
  return crypto_obj_.Hash(boost::any_cast<std::string>(params["publicname"]),
                          "", crypto::STRING_STRING, false);
}

PacketParams MpidPacket::GetData(const std::string &ser_packet,
      PacketParams) {
  PacketParams result;
  GenericPacket packet;
  if (!packet.ParseFromString(ser_packet)) {
    result["data"] = std::string("");
  } else {
    result["data"] = packet.data();
  }
  return result;
}

}  // namespace maidsafe
