/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  MaidSafe Passport Class
* Version:      1.0
* Created:      2010-10-13-14.01.23
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

#include "maidsafe/passport/passport.h"
#include <maidsafe/base/utils.h>
#include "maidsafe/passport/passportreturncodes.h"
#include "maidsafe/passport/systempackets.h"

namespace maidsafe {

namespace passport {

void Passport::Init(const boost::uint16_t &crypto_key_buffer_count) {
  crypto_key_buffer_count_ = crypto_key_buffer_count;
  crypto_key_pairs_.StartToCreateKeyPairs(crypto_key_buffer_count_);
}

int Passport::SetInitialDetails(const std::string &username,
                                const std::string &pin,
                                std::string *mid_name,
                                std::string *smid_name) {
  boost::shared_ptr<MidPacket> mid(new MidPacket(username, pin, ""));
  boost::shared_ptr<MidPacket> smid(new MidPacket(username, pin,
                                                  kSmidAppendix_));
  bool success(!mid->name().empty() && !smid->name().empty());
  if (success) {
    success = packet_handler_.AddPacket(mid, false) &&
              packet_handler_.AddPacket(smid, false);
  }
  if (mid_name)
    *mid_name = mid->name();
  if (smid_name)
    *smid_name = smid->name();
  return success ? kSuccess : kPassportError;
}

int Passport::SetNewUserData(const std::string &password,
                             const std::string &plain_data,
                             boost::shared_ptr<MidPacket> mid,
                             boost::shared_ptr<TmidPacket> tmid) {
  // Set RID for MID only
  boost::shared_ptr<MidPacket> retrieved_mid =
      boost::shared_static_cast<MidPacket>(packet_handler_.Packet(MID));
  if (!retrieved_mid.get())
    return kNoMid;
  boost::uint32_t rid(base::RandomUint32());
  int retries(0), max_retries(3);
  while (rid == 0 && retries < max_retries) {
    rid = base::RandomUint32();
    ++retries;
  }
  retrieved_mid->SetRid(rid);

  // Create TMID
  boost::shared_ptr<TmidPacket> new_tmid(
      new TmidPacket(retrieved_mid->username(), retrieved_mid->pin(), rid,
                     false, password, plain_data));
  bool success(!retrieved_mid->name().empty() && !tmid->name().empty());
  if (success)
    success = packet_handler_.AddPacket(tmid, false);

  // Copy packets
  if (success) {
    if (mid.get())
      *mid = *retrieved_mid;
    else
      mid.reset(new MidPacket(*retrieved_mid));
    if (tmid.get())
      *tmid = *new_tmid;
    else
      tmid.reset(new TmidPacket(*new_tmid));
    return kSuccess;
  } else {
    return kPassportError;
  }
}

int Passport::UpdateUserData(const std::string &plain_data,
                             std::string *mid_old_value,
                             std::string *smid_old_value,
                             boost::shared_ptr<MidPacket> updated_mid,
                             boost::shared_ptr<MidPacket> updated_smid,
                             boost::shared_ptr<TmidPacket> new_tmid,
                             boost::shared_ptr<TmidPacket> tmid_for_deletion) {
  if (!mid_old_value || !smid_old_value)
    return kPassportError;

  // Sets SMID's RID to MID's RID and generate new RID for MID
  boost::shared_ptr<MidPacket> retrieved_mid =
      boost::shared_static_cast<MidPacket>(packet_handler_.Packet(MID));
  boost::shared_ptr<MidPacket> retrieved_smid =
      boost::shared_static_cast<MidPacket>(packet_handler_.Packet(SMID));
  if (!retrieved_mid.get())
    return kNoMid;
  if (!retrieved_smid.get())
    return kNoSmid;
  *mid_old_value = retrieved_mid->value();
  *smid_old_value = retrieved_smid->value();
  boost::uint32_t new_rid(base::RandomUint32()), old_rid(retrieved_mid->rid());
  int retries(0), max_retries(3);
  while ((new_rid == 0 || new_rid == old_rid) && retries < max_retries) {
    new_rid = base::RandomUint32();
    ++retries;
  }
  retrieved_mid->SetRid(new_rid);
  retrieved_smid->SetRid(old_rid);

  // Retrieve current STMID (which is to be deleted) - won't exist if this is
  // first update
  boost::shared_ptr<TmidPacket> retrieved_stmid =
      boost::shared_static_cast<TmidPacket>(packet_handler_.Packet(STMID));

  // Set STMID as old TMID and create a new TMID
  boost::shared_ptr<TmidPacket> retrieved_tmid =
      boost::shared_static_cast<TmidPacket>(packet_handler_.Packet(TMID));
  if (!retrieved_tmid.get())
    return kNoTmid;
  boost::shared_ptr<TmidPacket> tmid(
      new TmidPacket(retrieved_tmid->username(), retrieved_tmid->pin(), new_rid,
                     false, retrieved_tmid->password(), plain_data));
  bool success(!tmid->name().empty());
  if (success) {
    retrieved_tmid->SetToSurrogate();
    success = packet_handler_.AddPacket(retrieved_tmid, true);
  }
  if (success)
    success = packet_handler_.AddPacket(tmid, true);

  // Copy packets
  if (success) {
    if (updated_mid.get())
      *updated_mid = *retrieved_mid;
    else
      updated_mid.reset(new MidPacket(*retrieved_mid));
    if (updated_smid.get())
      *updated_smid = *retrieved_smid;
    else
      updated_smid.reset(new MidPacket(*retrieved_smid));
    if (new_tmid.get())
      *new_tmid = *tmid;
    else
      new_tmid.reset(new TmidPacket(*tmid));
    if (retrieved_stmid.get()) {
      if (tmid_for_deletion.get())
        *tmid_for_deletion = *retrieved_stmid;
      else
        tmid_for_deletion.reset(new TmidPacket(*retrieved_stmid));
    }
    return kSuccess;
  } else {
    return kPassportError;
  }
}

int Passport::InitialiseTmid(bool surrogate,
                             const std::string &serialised_mid_packet,
                             std::string *tmid_name) {
  PacketType mid_type(MID);
  if (surrogate)
    mid_type = SMID;
  boost::shared_ptr<MidPacket> mid =
      boost::shared_static_cast<MidPacket>(packet_handler_.Packet(mid_type));
  if (!mid.get())
    return surrogate ? kNoSmid : kNoMid;
  if (mid->ParseRid(serialised_mid_packet) == 0)
    return surrogate ? kBadSerialisedSmidRid : kBadSerialisedMidRid;
  boost::shared_ptr<TmidPacket> tmid(new TmidPacket(mid->username(), mid->pin(),
                                     mid->rid(), surrogate, "", ""));
  bool success(!tmid->name().empty());
  if (success)
    success = packet_handler_.AddPacket(tmid, false);
  if (tmid_name)
    *tmid_name = tmid->name();
  return success ? kSuccess : kPassportError;
}

int Passport::GetUserData(const std::string &password,
                          bool surrogate,
                          const std::string &serialised_tmid_packet,
                          std::string *plain_data) {
  PacketType tmid_type(TMID);
  if (surrogate)
    tmid_type = STMID;
  boost::shared_ptr<TmidPacket> tmid =
      boost::shared_static_cast<TmidPacket>(packet_handler_.Packet(tmid_type));
  if (!tmid.get())
    return surrogate ? kNoStmid : kNoTmid;
  if (!plain_data)
    return kPassportError;
  *plain_data = tmid->ParsePlainData(password, serialised_tmid_packet);
  if (plain_data->empty())
    return surrogate ? kBadSerialisedStmidData : kBadSerialisedTmidData;
  else
    return kSuccess;
}

std::string Passport::SerialiseKeyring() {
  return packet_handler_.SerialiseKeyring();
}

int Passport::ParseKeyring(const std::string &serialised_keyring) {
  return packet_handler_.ParseKeyring(serialised_keyring);
}

int Passport::InitialiseSignaturePacket(
    const PacketType &packet_type,
    boost::shared_ptr<SignaturePacket> signature_packet) {
  return DoInitialiseSignaturePacket(packet_type, "", signature_packet);
}

int Passport::InitialiseMpid(const std::string &public_name,
                             boost::shared_ptr<SignaturePacket> mpid) {
  return DoInitialiseSignaturePacket(MPID, public_name, mpid);
}

int Passport::DoInitialiseSignaturePacket(
    const PacketType &packet_type,
    const std::string &public_name,
    boost::shared_ptr<SignaturePacket> signature_packet) {
  if (!IsSignature(packet_type, false))
    return kPassportError;
  PacketType signer_type(UNKNOWN);
  switch (packet_type) {
    case MPID:
      signer_type = ANMPID;
      break;
    case PMID:
      signer_type = MAID;
      break;
    case MAID:
      signer_type = ANMAID;
      break;
    default:
      break;
  }

  std::string signer_private_key;
  if (signer_type != UNKNOWN) {
    boost::shared_ptr<SignaturePacket> signer =
        boost::shared_static_cast<SignaturePacket>(
            packet_handler_.Packet(signer_type));
    if (!signer.get())
      return kNoSigningPacket;
    signer_private_key = signer->private_key();
  }
  crypto::RsaKeyPair key_pair;
  while (!crypto_key_pairs_.GetKeyPair(&key_pair)) {
    key_pair.ClearKeys();
    crypto_key_pairs_.StartToCreateKeyPairs(crypto_key_buffer_count_);
  }
  boost::shared_ptr<SignaturePacket> packet(
      new SignaturePacket(packet_type, key_pair.public_key(),
                          key_pair.private_key(), signer_private_key,
                          public_name));
  bool success(!packet->name().empty());
  if (success)
    success = packet_handler_.AddPacket(packet, true);
  if (success) {
    if (signature_packet.get())
      *signature_packet = *packet;
    else
      signature_packet.reset(new SignaturePacket(*packet));
    return kSuccess;
  } else {
    return kPassportError;
  }
}




}  // namespace passport

}  // namespace maidsafe
