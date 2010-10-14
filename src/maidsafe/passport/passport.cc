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
#include "maidsafe/passport/passportreturncodes.h"
#include "maidsafe/passport/systempackets.h"

namespace maidsafe {

namespace passport {

void Passport::Init(const boost::uint16_t &crypto_key_buffer_count) {
  crypto_key_pairs_.StartToCreateKeyPairs(crypto_key_buffer_count);
}

int Passport::SetInitialDetails(const std::string &username,
                                const std::string &pin,
                                std::string *mid_name,
                                std::string *smid_name) {
  boost::shared_ptr<MidPacket> mid(new MidPacket(username, pin, "", 0));
  boost::shared_ptr<MidPacket> smid(new MidPacket(username, pin, kSmidAppendix_,
                                                  0));
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

int Passport::InitialiseTmid(const std::string &password,
                             bool surrogate,
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
                                     password, mid->rid(), "", surrogate));
  bool success(!tmid->name().empty());
  if (success)
    success = packet_handler_.AddPacket(tmid, false);
  if (tmid_name)
    *tmid_name = tmid->name();
  return success ? kSuccess : kPassportError;
}

int Passport::GetUserData(bool surrogate,
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
  *plain_data = tmid->ParsePlainData(serialised_tmid_packet);
  if (plain_data->empty())
    return surrogate ? kBadSerialisedStmidData : kBadSerialisedTmidData;
  else
    return kSuccess;
}

//  rid_ = base::RandomUint32();
//  while (rid_ == 0)
//    rid_ = base::RandomUint32();


}  // namespace passport

}  // namespace maidsafe
