/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include "maidsafe/client/authentication.h"

#include <boost/array.hpp>
#include <boost/regex.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/lexical_cast.hpp>

#include <vector>

#include "maidsafe/maidsafe.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe {

char *utils_trim_right(char *szSource) {
  char *pszEOS = 0;
  //  Set pointer to character before terminating NULL
  pszEOS = szSource + strlen(szSource) - 1;
  //  iterate backwards until non '_' is found
  while ((pszEOS >= szSource) && (*pszEOS == ' '))
    --*pszEOS = '\0';
  return szSource;
}

char *utils_trim_left(char *szSource) {
  char *pszBOS = 0;
  //  Set pointer to character before terminating NULL
  // pszEOS = szSource + strlen(szSource) - 1;
  pszBOS = szSource;
  //  iterate backwards until non '_' is found
  while (*pszBOS == ' ')
    ++*pszBOS;
  return pszBOS;
}

char *utils_trim(char *szSource) {
  return utils_trim_left(utils_trim_right(utils_trim_left(szSource)));
}

void Authentication::Init(boost::shared_ptr<StoreManagerInterface> smgr) {
  sm_ = smgr;
  ss_ = SessionSingleton::getInstance();
  crypto_.set_hash_algorithm(crypto::SHA_512);
  crypto_.set_symm_algorithm(crypto::AES_256);
}

int Authentication::GetUserInfo(const std::string &username,
                                const std::string &pin) {
  ss_->SetSmidRid(0);
  tmid_content_ = "";
  int rid = 0;
  bool smid = false;
  if (!GetMid(username, pin, &rid)) {
    if (!GetSmid(username, pin, &rid)) {
      ss_->ResetSession();
      return kUserDoesntExist;
    }
    ss_->SetSmidRid(rid);
    smid = true;
  }
  if (rid == 0) {
    ss_->ResetSession();
    return kInvalidUsernameOrPin;
  }
  ss_->SetMidRid(rid);
  ss_->SetUsername(username);
  ss_->SetPin(pin);

  // Getting tmid
  GetUserTmid(smid);
  if (tmid_content_ == "") {
#ifdef DEBUG
    printf("Authentication::GetUserInfo - no TMID after GetUserTmid.\n");
#endif
    return kAuthenticationError;
  }

  return kUserExists;
}

int Authentication::GetUserData(const std::string &password,
                                std::string &ser_da) {
  //  still have not recovered the tmid
  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));
  PacketParams rec_data = tmidPacket->GetData(tmid_content_, password,
                          ss_->MidRid());
  ser_da = boost::any_cast<std::string>(rec_data["data"]);

  DataMap dm;
  if (!dm.ParseFromString(ser_da))
    return kPasswordFailure;
  ss_->SetPassword(password);
  return kSuccess;
}

int Authentication::CreateUserSysPackets(const std::string &username,
                                         const std::string &pin) {
  system_packets_result_ = kPendingResult;
  PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));

  boost::uint16_t count(0);
  bool calledback(false);
  VoidFuncOneInt func = boost::bind(
      &Authentication::CreateSystemPacketsCallback, this, _1);
  sm_->KeyUnique(midPacket->PacketName(&params), false, boost::bind(
      &Authentication::CreateUserSysPackets, this, _1, username, pin, func,
      &count, &calledback));
  sm_->KeyUnique(smidPacket->PacketName(&params), false, boost::bind(
      &Authentication::CreateUserSysPackets, this, _1, username, pin, func,
      &count, &calledback));

  while (system_packets_result_ == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

  return system_packets_result_;
}

void Authentication::CreateUserSysPackets(const ReturnCode rc,
                                          const std::string &username,
                                          const std::string &pin,
                                          VoidFuncOneInt vfoi,
                                          boost::uint16_t *count,
                                          bool *calledback) {
  if (*calledback)
    return;
  if (rc == kKeyUnique) {
    if (*count == 0) {
      ++*count;
      return;
    }
  } else {
    *calledback = true;
    vfoi(kUserExists);
    return;
  }
  boost::array<PacketType, 3> anonymous = { {ANMAID, ANMID, ANTMID} };
  boost::shared_ptr<SystemPacketCreation> data(new SystemPacketCreation());
  data->username = username;
  data->pin = pin;
  data->vfoi = vfoi;
  for (size_t n = 0; n < anonymous.size(); ++n)
    CreateSignaturePacket(data, anonymous[n]);
}

void Authentication::CreateSignaturePacket(
    boost::shared_ptr<SystemPacketCreation> spc,
    const PacketType &type_da) {
  PacketParams params;
  boost::scoped_ptr<SignaturePacket> sigPacket(
      static_cast<SignaturePacket*>(PacketFactory::Factory(type_da)));
  sigPacket->Create(&params);
  boost::shared_ptr<FindSystemPacket> fsp(new FindSystemPacket());
  fsp->spc = spc;
  fsp->pp = params;
  fsp->pt = type_da;

  VoidFuncOneInt func = boost::bind(
      &Authentication::CreateSignaturePacketKeyUnique, this, _1, fsp);
  sm_->KeyUnique(boost::any_cast<std::string>(params["name"]), false, func);
}

void Authentication::CreateSignaturePacketKeyUnique(
    const ReturnCode &rc,
    boost::shared_ptr<FindSystemPacket> fsp) {
  if (rc == kKeyUnique) {
    int n = ss_->AddKey(fsp->pt,
                        boost::any_cast<std::string>(fsp->pp["name"]),
                        boost::any_cast<std::string>(fsp->pp["privateKey"]),
                        boost::any_cast<std::string>(fsp->pp["publicKey"]),
                        "");
    if (n != 0) {
      // return to CreateSignaturePacket
    }

    VoidFuncOneInt func = boost::bind(
        &Authentication::CreateSignaturePacketStore, this, _1, fsp);
    sm_->StorePacket(boost::any_cast<std::string>(fsp->pp["name"]),
                     boost::any_cast<std::string>(fsp->pp["publicKey"]),
                     fsp->pt, PRIVATE, "", kDoNothingReturnFailure, func);
  } else {
    // return to CreateSignaturePacket
  }
}

void Authentication::CreateSignaturePacketStore(
    const ReturnCode &rc,
    boost::shared_ptr<FindSystemPacket> fsp) {
  if (rc == kSuccess) {
    ++fsp->spc->packet_count;
    switch (fsp->pt) {
      case ANMAID:
        fsp->pt = MAID;
        CreateMaidPmidPacket(fsp);
        break;
      case ANMID:
        CreateMidPacket(fsp);
        break;
      case MID:
        CreateSignaturePacket(fsp->spc, ANSMID);
        break;
      case ANSMID:
        CreateSmidPacket(fsp);
        break;
      case MAID:
        fsp->pt = PMID;
        CreateMaidPmidPacket(fsp);
        break;
      default:
        if (fsp->spc->packet_count == NoOfSystemPackets)
          fsp->spc->vfoi(kSuccess);
    }
  } else {
    ss_->RemoveKey(fsp->pt);
  }
}

void Authentication::CreateMidPacket(boost::shared_ptr<FindSystemPacket> fsp) {
  fsp->pt = MID;
  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  PacketParams user_params;
  user_params["username"] = fsp->spc->username;
  user_params["PIN"] = fsp->spc->pin;
  user_params["privateKey"] = ss_->PrivateKey(ANMID);
  std::string public_key;

  PacketParams mid_result = midPacket->Create(&user_params);
  ss_->SetMidRid(boost::any_cast<boost::uint32_t>(mid_result["rid"]));

  sm_->StorePacket(boost::any_cast<std::string>(mid_result["name"]),
                   boost::any_cast<std::string>(mid_result["encRid"]),
                   MID, PRIVATE, "", kDoNothingReturnFailure,
                   boost::bind(&Authentication::CreateSignaturePacketStore,
                               this, _1, fsp));
}

void Authentication::CreateSmidPacket(boost::shared_ptr<FindSystemPacket> fsp) {
  fsp->pt = SMID;
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));
  PacketParams user_params;
  user_params["username"] = fsp->spc->username;
  user_params["PIN"] = fsp->spc->pin;
  user_params["privateKey"] = ss_->PrivateKey(ANSMID);
  user_params["rid"] = ss_->MidRid();
  std::string public_key;

  PacketParams smid_result = smidPacket->Create(&user_params);
  ss_->SetSmidRid(ss_->MidRid());
  sm_->StorePacket(boost::any_cast<std::string>(smid_result["name"]),
                   boost::any_cast<std::string>(smid_result["encRid"]),
                   SMID, PRIVATE, "", kDoNothingReturnFailure,
                   boost::bind(&Authentication::CreateSignaturePacketStore,
                               this, _1, fsp));
}

void Authentication::CreateMaidPmidPacket(
    boost::shared_ptr<FindSystemPacket> fsp) {
  boost::scoped_ptr<PmidPacket> packet(
    static_cast<PmidPacket*>(PacketFactory::Factory(PMID)));
  PacketParams user_params;
  if (fsp->pt == PMID) {
    user_params["privateKey"] = ss_->PrivateKey(MAID);
  } else {
    user_params["privateKey"] = ss_->PrivateKey(ANMAID);
  }

  PacketParams result = packet->Create(&user_params);
  int n = ss_->AddKey(fsp->pt,
                      boost::any_cast<std::string>(result["name"]),
                      boost::any_cast<std::string>(result["privateKey"]),
                      boost::any_cast<std::string>(result["publicKey"]),
                      boost::any_cast<std::string>(result["signature"]));
  if (n != 0) {
    // return to CreateSignaturePacket
  }
  sm_->StorePacket(boost::any_cast<std::string>(result["name"]),
                   boost::any_cast<std::string>(result["publicKey"]),
                   fsp->pt, PRIVATE, "", kDoNothingReturnFailure,
                   boost::bind(&Authentication::CreateSignaturePacketStore,
                               this, _1, fsp));
}

int Authentication::CreateTmidPacket(const std::string &username,
                                     const std::string &pin,
                                     const std::string &password,
                                     const std::string &ser_dm) {
  PacketParams user_params;
  user_params["username"] = username;
  user_params["PIN"] = pin;
  user_params["privateKey"] = ss_->PrivateKey(ANTMID);
  user_params["password"] = password;
  user_params["rid"] = ss_->MidRid();

  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));

  // STORING SERLIALISED DATA MAP OF DATA ATLAS
  user_params["data"] = ser_dm;
  PacketParams tmid_result = tmidPacket->Create(&user_params);
  if (StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["data"]), TMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    ss_->SetMidRid(0);
    ss_->SetSmidRid(0);
    return kAuthenticationError;
  }

  ss_->SetUsername(username);
  ss_->SetPin(pin);
  ss_->SetPassword(password);

  return kSuccess;
}

int Authentication::SaveSession(const std::string &ser_da) {
  PacketParams params;
  PacketParams result;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();

  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));
  if (ss_->MidRid() != ss_->SmidRid()) {
    params["rid"] = ss_->MidRid();
    params["privateKey"] = ss_->PrivateKey(ANSMID);
    result = smidPacket->Create(&params);
    if (StorePacket(boost::any_cast<std::string>(result["name"]),
        boost::any_cast<std::string>(result["encRid"]), SMID, kOverwrite, "")
        != kSuccess) {
      return kAuthenticationError;
    }

    params["rid"] = ss_->SmidRid();
    std::string tmidname = tmidPacket->PacketName(&params);
    if (DeletePacket(tmidname, "", TMID) != kSuccess)
      return kAuthenticationError;

    ss_->SetSmidRid(ss_->MidRid());
  }

  params["privateKey"] = ss_->PrivateKey(ANMID);
  PacketParams mid_result = midPacket->Create(&params);
  while (ss_->MidRid() == boost::any_cast<boost::uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(&params);

  params["privateKey"] = ss_->PrivateKey(ANTMID);
  params["rid"] = boost::any_cast<boost::uint32_t>(mid_result["rid"]);
  params["password"] = ss_->Password();
  params["data"] = ser_da;
  PacketParams tmidresult = tmidPacket->Create(&params);
  if (StorePacket(boost::any_cast<std::string>(tmidresult["name"]),
      boost::any_cast<std::string>(tmidresult["data"]), TMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }

  if (StorePacket(boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["encRid"]), MID, kOverwrite, "")
      != kSuccess) {
    return kAuthenticationError;
  }

  ss_->SetMidRid(boost::any_cast<boost::uint32_t>(mid_result["rid"]));

  return kSuccess;
}

int Authentication::RemoveMe(std::list<KeyAtlasRow> sig_keys) {
  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));
  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));

  PacketParams params;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();

  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  params["rid"] = ss_->MidRid();
  std::string mpid_name, pmid_name;

  while (!sig_keys.empty()) {
    KeyAtlasRow kt = sig_keys.front();
    sig_keys.pop_front();
    switch (kt.type_) {
      case ANMID:
          DeletePacket(midPacket->PacketName(&params), "",
                       static_cast<PacketType>(kt.type_));
          break;
      case ANSMID:
          DeletePacket(smidPacket->PacketName(&params), "",
                       static_cast<PacketType>(kt.type_));
          break;
      case ANTMID:
          DeletePacket(tmidPacket->PacketName(&params), "",
                       static_cast<PacketType>(kt.type_));
          params["rid"] = ss_->SmidRid();
          if (ss_->SmidRid() != ss_->MidRid())
            DeletePacket(tmidPacket->PacketName(&params), "",
                         static_cast<PacketType>(kt.type_));
          break;
      case ANMPID:
          DeletePacket(mpid_name, "", static_cast<PacketType>(kt.type_));
          break;
      case MAID:
          if (!pmid_name.empty())
            DeletePacket(pmid_name, "", static_cast<PacketType>(kt.type_));
          break;
      case MPID: mpid_name = kt.id_; break;
      case PMID: pmid_name = kt.id_; break;
    }
    DeletePacket(kt.id_, "", static_cast<PacketType>(kt.type_));
  }
  return kSuccess;
}

int Authentication::CreatePublicName(const std::string &public_username) {
  PacketParams params;
  PacketParams local_result;
  params["publicname"] = public_username;
  boost::scoped_ptr<MpidPacket> mpidPacket(
      static_cast<MpidPacket*>(PacketFactory::Factory(MPID)));
  std::string mpidname = mpidPacket->PacketName(&params);

  if (!sm_->KeyUnique(mpidname, false)) {
#ifdef DEBUG
    printf("Authentication::CreatePublicName - Exists\n");
#endif
    return kPublicUsernameExists;
  }

  boost::scoped_ptr<SignaturePacket> sigPacket(
      static_cast<SignaturePacket*>(PacketFactory::Factory(ANMPID)));
  sigPacket->Create(&params);
  while (!sm_->KeyUnique(boost::any_cast<std::string>(params["name"]),
         false))
    sigPacket->Create(&params);

  ss_->AddKey(ANMPID, boost::any_cast<std::string>(params["name"]),
              boost::any_cast<std::string>(params["privateKey"]),
              boost::any_cast<std::string>(params["publicKey"]),
              "");
  if (StorePacket(boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["ser_packet"]), ANMPID,
      kDoNothingReturnFailure, "") != kSuccess) {
#ifdef DEBUG
    printf("Authentication::CreatePublicName - Buggered in ANMPID\n");
#endif
    ss_->RemoveKey(ANMPID);
    return kAuthenticationError;
  }

  PacketParams mpid_result = mpidPacket->Create(&params);
  std::string data = boost::any_cast<std::string>(mpid_result["publicKey"]);
  std::string pubkey_signature = crypto_.AsymSign(data, "",
                                 ss_->PrivateKey(ANMPID),
                                 crypto::STRING_STRING);

  if (StorePacket(boost::any_cast<std::string>(mpid_result["name"]), data,
      MPID, kDoNothingReturnFailure, "") != kSuccess) {
#ifdef DEBUG
    printf("Authentication::CreatePublicName - Buggered in MPID\n");
#endif
    ss_->RemoveKey(ANMPID);
    return kAuthenticationError;
  }

  ss_->AddKey(MPID,
              public_username,
              boost::any_cast<std::string>(mpid_result["privateKey"]),
              boost::any_cast<std::string>(mpid_result["publicKey"]),
              pubkey_signature);

  return kSuccess;
}

int Authentication::ChangeUsername(const std::string &ser_da,
                                   const std::string &new_username) {
//  if (!CheckUsername(new_username) || new_username == ss_->Username())
//    return INVALID_USERNAME;
  int fakerid;
  if (GetMid(new_username, ss_->Pin(), &fakerid))
    return kUserExists;

  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  PacketParams user_params;
  user_params["username"] = new_username;
  user_params["PIN"] = ss_->Pin();
  std::string mid_name = midPacket->PacketName(&user_params);

  //  Getting SMID Rid for current username
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));
  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  //  Creating and storing new MID packet with new username
  user_params["privateKey"] = ss_->PrivateKey(ANMID);
  PacketParams mid_result = midPacket->Create(&user_params);
  while (ss_->MidRid() == boost::any_cast<boost::uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(&user_params);

  if (StorePacket(boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["encRid"]), MID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  //  Creating and storing new SMID packet with new username and old MID Rid
  user_params["privateKey"] = ss_->PrivateKey(ANSMID);
  user_params["rid"] = ss_->MidRid();

  PacketParams smid_result = smidPacket->Create(&user_params);
  if (StorePacket(boost::any_cast<std::string>(smid_result["name"]),
      boost::any_cast<std::string>(smid_result["encRid"]), SMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  //  Creating new TMID-->MID with new MID Rid
  user_params["privateKey"] = ss_->PrivateKey(ANTMID);
  user_params["password"] = ss_->Password();
  user_params["rid"] = boost::any_cast<boost::uint32_t>(mid_result["rid"]);
  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));
  user_params["data"] = ser_da;
  PacketParams tmid_result = tmidPacket->Create(&user_params);
  if (StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["data"]), TMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  //  Creating new TMID-->SMID with old MID Rid and pointing to old DA
  PacketParams old_user_params;
  old_user_params["username"] = ss_->Username();
  old_user_params["PIN"] = ss_->Pin();
  old_user_params["rid"] = ss_->MidRid();

  std::vector<std::string> packet_content;
  int result = sm_->LoadPacket(tmidPacket->PacketName(
      &old_user_params), &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kAuthenticationError;
  std::string ser_tmid = packet_content[0];
  PacketParams rec_tmid = tmidPacket->GetData(ser_tmid, ss_->Password(),
                          ss_->MidRid());
  std::string tmid_data = boost::any_cast<std::string>(rec_tmid["data"]);
  if (tmid_data == "")
    return kAuthenticationError;
  old_user_params["data"] = tmid_data;
  old_user_params["privateKey"] = ss_->PrivateKey(ANTMID);
  old_user_params["password"] = ss_->Password();
  old_user_params["username"] = new_username;
  tmid_result = tmidPacket->Create(&old_user_params);
  if (StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["data"]), TMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  user_params["username"] = ss_->Username();

//  printf("++++++ %s - %s\n",
//         HexSubstr(midPacket->PacketName(&user_params)).c_str(),
//         HexSubstr(EncryptedDataMidSmid(boost::any_cast<boost::uint32_t>(
//                   old_user_params["rid"]))).c_str());
  result = DeletePacket(midPacket->PacketName(&user_params),
           EncryptedDataMidSmid(boost::any_cast<boost::uint32_t>(
           old_user_params["rid"])), MID);
//  printf("------ %s - %s\n",
//         HexSubstr(midPacket->PacketName(&user_params)).c_str(),
//         HexSubstr(EncryptedDataMidSmid(ss_->SmidRid())).c_str());
  result = DeletePacket(smidPacket->PacketName(&user_params),
           EncryptedDataMidSmid(ss_->SmidRid()), SMID);
  user_params["rid"] = ss_->MidRid();
  result = DeletePacket(tmidPacket->PacketName(&user_params), "", TMID);
  if (ss_->MidRid() != ss_->SmidRid()) {
    user_params["rid"] = ss_->SmidRid();
    result = DeletePacket(tmidPacket->PacketName(&user_params), "", TMID);
  }

  ss_->SetUsername(new_username);
  ss_->SetSmidRid(ss_->MidRid());
  ss_->SetMidRid(boost::any_cast<boost::uint32_t>(mid_result["rid"]));

  return kSuccess;
}

int Authentication::ChangePin(const std::string &ser_da,
                              const std::string &new_pin) {
//  if (!CheckPin(new_pin) || new_pin == ss_->Pin())
//    return INVALID_PIN;
  int fakerid;
  if (GetMid(ss_->Username(), new_pin, &fakerid))
    return kUserExists;

  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  PacketParams user_params;
  user_params["username"] = ss_->Username();
  user_params["PIN"] = new_pin;
  std::string mid_name = midPacket->PacketName(&user_params);
  boost::uint32_t old_mid_rid(ss_->MidRid()), old_smid_rid(ss_->SmidRid());

  //  Getting SMID Rid for current username
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));
  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
    old_smid_rid = ss_->SmidRid();
  }

  //  Creating and storing new MID packet with new username
  user_params["privateKey"] = ss_->PrivateKey(ANMID);
  PacketParams mid_result = midPacket->Create(&user_params);
  while (ss_->MidRid() == boost::any_cast<boost::uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(&user_params);

  if (StorePacket(boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["encRid"]), MID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  //  Creating and storing new SMID packet with new username and old MID Rid
  user_params["privateKey"] = ss_->PrivateKey(ANSMID);
  user_params["rid"] = ss_->MidRid();

  PacketParams smid_result = smidPacket->Create(&user_params);
  if (StorePacket(boost::any_cast<std::string>(smid_result["name"]),
      boost::any_cast<std::string>(smid_result["encRid"]), SMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  //  Creating new TMID-->MID with new MID Rid
  user_params["privateKey"] = ss_->PrivateKey(ANTMID);
  user_params["password"] = ss_->Password();
  user_params["rid"] = boost::any_cast<boost::uint32_t>(mid_result["rid"]);
  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));
  user_params["data"] = ser_da;
  PacketParams tmid_result = tmidPacket->Create(&user_params);
  if (StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["data"]), TMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  //  Creating new TMID-->SMID with old MID Rid and pointing to old DA
  PacketParams old_user_params;
  old_user_params["username"] = ss_->Username();
  old_user_params["PIN"] = ss_->Pin();
  old_user_params["rid"] = ss_->MidRid();

  std::vector<std::string> packet_content;
  int result = sm_->LoadPacket(tmidPacket->PacketName(
      &old_user_params), &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kAuthenticationError;
  std::string ser_tmid = packet_content[0];
  PacketParams rec_tmid = tmidPacket->GetData(ser_tmid, ss_->Password(),
                          ss_->MidRid());
  std::string tmid_data = boost::any_cast<std::string>(rec_tmid["data"]);
  if (tmid_data == "")
    return kAuthenticationError;
  old_user_params["data"] = tmid_data;
  old_user_params["privateKey"] = ss_->PrivateKey(ANTMID);
  old_user_params["password"] = ss_->Password();
  old_user_params["PIN"] = new_pin;
  tmid_result = tmidPacket->Create(&old_user_params);
  if (StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["data"]), TMID,
      kDoNothingReturnFailure, "") != kSuccess) {
    return kAuthenticationError;
  }
  user_params["PIN"] = ss_->Pin();

//  printf("++++++ %s - %s\n",
//         HexSubstr(midPacket->PacketName(&user_params)).c_str(),
//         HexSubstr(EncryptedDataMidSmid(boost::any_cast<boost::uint32_t>(
//                   old_user_params["rid"]))).c_str());

  result = DeletePacket(midPacket->PacketName(&user_params),
           EncryptedDataMidSmid(old_mid_rid), MID);
//  printf("------ %s - %s\n",
//         HexSubstr(midPacket->PacketName(&user_params)).c_str(),
//         HexSubstr(EncryptedDataMidSmid(ss_->SmidRid())).c_str());
  result = DeletePacket(smidPacket->PacketName(&user_params),
           EncryptedDataMidSmid(old_smid_rid), SMID);
  user_params["rid"] = ss_->MidRid();
  result = DeletePacket(tmidPacket->PacketName(&user_params), "", TMID);
  if (ss_->MidRid() != ss_->SmidRid()) {
    user_params["rid"] = ss_->SmidRid();
    result = DeletePacket(tmidPacket->PacketName(&user_params), "", TMID);
  }

  ss_->SetPin(new_pin);
  ss_->SetSmidRid(ss_->MidRid());
  ss_->SetMidRid(boost::any_cast<boost::uint32_t>(mid_result["rid"]));

  return kSuccess;
}

int Authentication::ChangePassword(const std::string &ser_da,
                                   const std::string &new_password) {
//  if (!CheckPassword(new_password) || new_password == ss_->Password())
//    return INVALID_PASSWORD;
  std::string old_password = ss_->Password();
  ss_->SetPassword(new_password);
  if (SaveSession(ser_da) == kSuccess) {
    return kSuccess;
  } else {
    ss_->SetPassword(old_password);
    return kAuthenticationError;
  }
}

std::string Authentication::CreateSignaturePackets(const PacketType &type_da,
                                                   std::string *public_key) {
  PacketParams params;
  boost::scoped_ptr<SignaturePacket> sigPacket(
      static_cast<SignaturePacket*>(PacketFactory::Factory(type_da)));
  sigPacket->Create(&params);

  while (!sm_->KeyUnique(boost::any_cast<std::string>(params["name"]), false))
    sigPacket->Create(&params);

  ss_->AddKey(type_da,
              boost::any_cast<std::string>(params["name"]),
              boost::any_cast<std::string>(params["privateKey"]),
              boost::any_cast<std::string>(params["publicKey"]),
              "");

  if (StorePacket(boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["ser_packet"]), type_da,
      kDoNothingReturnFailure, "") != kSuccess) {
    ss_->RemoveKey(type_da);
    return "";
  }

  *public_key = boost::any_cast<std::string>(params["publicKey"]);
  return boost::any_cast<std::string>(params["privateKey"]);
}

bool Authentication::CheckUsername(const std::string &username) {
  std::string username_ = utils_trim(boost::lexical_cast<char*>(username));
  return (username_.length() >= 4);
}

bool Authentication::CheckPin(const std::string &pin) {
  std::string pin_ = utils_trim(boost::lexical_cast<char*>(pin));
  if (pin_ == "0000")
    return false;
  boost::regex re("\\d{4}");
  return boost::regex_match(pin_, re);
}

bool Authentication::CheckPassword(const std::string &password) {
  std::string password_ = utils_trim(boost::lexical_cast<char*>(password));
  return (password_.length() >= 4);
}

bool Authentication::GetMid(const std::string &username,
                            const std::string &pin,
                            int *rid) {
  PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  boost::scoped_ptr<MidPacket> midPacket(
      static_cast<MidPacket*>(PacketFactory::Factory(MID)));
  std::string mid_name = midPacket->PacketName(&params);

  std::string ser_packet;
  std::vector<std::string> packet_content;
  int result = sm_->LoadPacket(mid_name, &packet_content);
  if (result != kSuccess || packet_content.empty()) {
    return false;
  }
  ser_packet = packet_content[0];
  PacketParams info = midPacket->GetData(ser_packet, username, pin);
  // The key of mid_name clashed with another value that is not a mid
  // hence, it could not recover a valid mid but we can not return false
  // because that would mean it doesn't exist
  boost::uint32_t rec_data = boost::any_cast<boost::uint32_t>(info["data"]);
  if (rec_data == 0) {
    *rid = 0;
    return true;
  }
  *rid = rec_data;
  return true;
}

bool Authentication::GetSmid(const std::string &username,
                             const std::string &pin,
                             int *rid) {
  PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  boost::scoped_ptr<SmidPacket> smidPacket(
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID)));
  std::string smid_name = smidPacket->PacketName(&params);
  std::string ser_packet;
  std::vector<std::string> packet_content;
  int result = sm_->LoadPacket(smid_name, &packet_content);
  if (result != kSuccess || packet_content.empty()) {
    return false;
  }
  ser_packet = packet_content[0];
  PacketParams info = smidPacket->GetData(ser_packet, username, pin);
  boost::uint32_t rec_data = boost::any_cast<boost::uint32_t>(info["data"]);
  if (rec_data != 0) {
    // The key of mid_name clashed with another value that is not a smid.
    // It could not recover a valid smid but we can not return false
    // because that would mean it doesn't exists
    *rid = 0;
    return false;
  }
  *rid = rec_data;
  return true;
}

void Authentication::GetUserTmid(bool smid) {
  boost::scoped_ptr<TmidPacket> tmidPacket(
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID)));
  PacketParams params;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();
  params["rid"] = ss_->MidRid();
  std::string tmid_name = tmidPacket->PacketName(&params);
  std::vector<std::string> packet_content;
  int result = sm_->LoadPacket(tmid_name, &packet_content);
  if (result != kSuccess || packet_content.empty()) {
    if (smid) {
#ifdef DEBUG
      printf("Authentication::GetUserTmid - Failure 1\n");
#endif
      return;
    }
    if (ss_->SmidRid() == 0) {
      int rid;
      if (!GetSmid(ss_->Username(), ss_->Pin(), &rid)) {
#ifdef DEBUG
        printf("Authentication::GetUserTmid - No SMID either.\n");
#endif
        return;
      }
      ss_->SetSmidRid(rid);
      ss_->SetMidRid(rid);
      GetUserTmid(true);
      return;
    } else {
#ifdef DEBUG
      printf("Authentication::GetUserTmid - Failure 2\n");
#endif
      return;
    }
  }
  tmid_content_ = packet_content[0];
#ifdef DEBUG
  printf("Authentication::GetUserTmidCallback returning content.\n");
#endif
}

int Authentication::PublicUsernamePublicKey(const std::string &public_username,
                                            std::string *public_key) {
  PacketParams params;
  params["publicname"] = public_username;
  boost::scoped_ptr<MpidPacket> mpidPacket(
      static_cast<MpidPacket*>(PacketFactory::Factory(MPID)));

  std::vector<std::string> packet_content;
  int result = sm_->LoadPacket(mpidPacket->PacketName(&params),
                                         &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kUserDoesntExist;
  std::string ser_generic_packet = packet_content[0];
  GenericPacket gp;
  if (!gp.ParseFromString(ser_generic_packet)) {
    return kAuthenticationError;  //  Packet corrupt
  }

  *public_key = gp.data();

  return kSuccess;
}

void Authentication::CreateMSIDPacket(base::callback_func_type cb) {
  PacketParams params;
  boost::scoped_ptr<SignaturePacket> sigPacket(
      static_cast<SignaturePacket*>(PacketFactory::Factory(MSID)));
  sigPacket->Create(&params);

  int count = 0;
  while (!sm_->KeyUnique(boost::any_cast<std::string>(params["name"]),
         false) && count < 10)
    ++count;

  if (count > 9) {
    CreateMSIDResult local_result;
    local_result.set_result(kNack);
    std::string ser_local_result;
    local_result.SerializeToString(&ser_local_result);
    cb(ser_local_result);
    return;
  }

  std::vector<boost::uint32_t> share_stats(2, 0);
  std::vector<std::string> atts;
  atts.push_back(boost::any_cast<std::string>(params["name"]));
  atts.push_back(boost::any_cast<std::string>(params["name"]));
  atts.push_back(boost::any_cast<std::string>(params["publicKey"]));
  atts.push_back(boost::any_cast<std::string>(params["privateKey"]));
  int n = ss_->AddPrivateShare(atts, share_stats, NULL);

  n = StorePacket(boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["publicKey"]), MSID,
      kDoNothingReturnFailure, boost::any_cast<std::string>(params["name"]));
  ss_->DeletePrivateShare(atts[0], 0);

  StoreChunkResponse result_msg;
  CreateMSIDResult local_result;
  std::string str_local_result;
  if (n != 0) {
    local_result.set_result(kNack);
  } else {
    local_result.set_result(kAck);
    local_result.set_private_key(boost::any_cast<std::string>(
        params["privateKey"]));
    local_result.set_public_key(boost::any_cast<std::string>(
        params["publicKey"]));
    local_result.set_name(boost::any_cast<std::string>(params["name"]));
  }
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

int Authentication::StorePacket(const std::string &packet_name,
                                const std::string &value,
                                const PacketType &type,
                                const IfPacketExists &if_exists,
                                const std::string &msid) {
// TODO(Fraser#5#): 2010-01-28 - Use callbacks properly to allow several stores
//                               to happen concurrently.
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int result(kGeneralError);
  VoidFuncOneInt func = boost::bind(&Authentication::PacketOpCallback, this, _1,
                                    &mutex, &cond_var, &result);
  sm_->StorePacket(packet_name, value, type, PRIVATE, msid, if_exists, func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError)
      cond_var.wait(lock);
  }
  return result;
}

int Authentication::DeletePacket(const std::string &packet_name,
                                 const std::string &value,
                                 const PacketType &type) {
// TODO(Fraser#5#): 2010-01-28 - Use callbacks properly to allow several deletes
//                               to happen concurrently.
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int result(kGeneralError);
  VoidFuncOneInt func = boost::bind(&Authentication::PacketOpCallback, this, _1,
                                    &mutex, &cond_var, &result);
  std::vector<std::string> values(1, value);
  sm_->DeletePacket(packet_name, values, type, PRIVATE, "", func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError)
      cond_var.wait(lock);
  }
  return result;
}

void Authentication::PacketOpCallback(const int &store_manager_result,
                                      boost::mutex *mutex,
                                      boost::condition_variable *cond_var,
                                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

std::string Authentication::EncryptedDataMidSmid(boost::uint32_t rid) {
  std::string password = crypto_.SecurePassword(ss_->Username(),
                         boost::lexical_cast<boost::uint16_t>(ss_->Pin()));
  return crypto_.SymmEncrypt(boost::lexical_cast<std::string>(rid), "",
                             crypto::STRING_STRING, password);
}

}  // namespace maidsafe
