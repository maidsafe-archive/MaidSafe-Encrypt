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

#include <boost/regex.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/lexical_cast.hpp>
#include <cstdio>

#include "maidsafe/maidsafe.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe {

AuthCallbackResult::AuthCallbackResult() : result("") {}

void AuthCallbackResult::CallbackFunc(const std::string &res) {
  result = res;
}

void AuthCallbackResult::Reset() {
  result = "";
}

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

Authentication::Authentication(StoreManagerInterface *storemanager)
    : ud_(),
      mutex_(),
      crypto_(),
      storemanager_(storemanager),
      ss_(SessionSingleton::getInstance()),
      tmid_content_() {
  ss_->ResetSession();
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
    printf("Authentication::GetUserInfo - no TMID after GetUserTmid\n");
#endif
    return kAuthenticationError;
  }

  return kUserExists;
}

int Authentication::GetUserData(const std::string &password,
                                std::string &ser_da) {
  //  still have not recovered the tmid
  TmidPacket *tmidPacket =
    static_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  PacketParams rec_data = tmidPacket->GetData(tmid_content_, password,
      ss_->MidRid());
  ser_da = boost::any_cast<std::string>(rec_data["data"]);

  DataAtlas da;
  if (!da.ParseFromString(ser_da))
    return kPasswordFailure;
  ss_->SetPassword(password);
  return kSuccess;
}

int Authentication::CreateUserSysPackets(const std::string &username,
                                         const std::string &pin,
                                         const std::string &password) {
//  int fakerid = 0;
//  if (GetMid(username, pin, &fakerid))
//    return kUserExists;

  PacketParams check_unique_params;
  check_unique_params["username"] = username;
  check_unique_params["PIN"] = pin;
  MidPacket *check_unique_mid_packet =
      static_cast<MidPacket*>(PacketFactory::Factory(MID));
  std::string check_unique_mid_name =
      check_unique_mid_packet->PacketName(&check_unique_params);

  if (!storemanager_->KeyUnique(check_unique_mid_name, false))
    return kUserExists;

  MidPacket *midPacket =
      static_cast<MidPacket*>(PacketFactory::Factory(MID));
  PacketParams user_params;
  user_params["username"] = username;
  user_params["PIN"] = pin;
  DataAtlas data_atlas;
  std::string public_key;

  user_params["privateKey"] =
      createSignaturePackets(ANMID, public_key);
  PacketParams mid_result = midPacket->Create(&user_params);
  int n = storemanager_->StorePacket(
      boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["ser_packet"]), MID, PRIVATE,
      "");
  if (n != kSuccess) {
    printf("Fucked in MID store: %i\n", n);
    return kAuthenticationError;
  }

  printf("AAAAAAAAAAAAAA\n");
  user_params["privateKey"] =
      createSignaturePackets(ANSMID, public_key);
  SmidPacket *smidPacket =
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  PacketParams smid_result = smidPacket->Create(&user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(smid_result["name"]),
      boost::any_cast<std::string>(smid_result["ser_packet"]), SMID,
      PRIVATE, "") != kSuccess) {
    return kAuthenticationError;
  }

  printf("BBBBBBBBBBBBBB\n");
  std::string privkey = createSignaturePackets(MAID, public_key);

  // user_params["privateKey"] =
  //  createSignaturePackets(PMID, PMID, data_atlas, public_key);
  user_params["privateKey"] = privkey;
  PmidPacket *pmidPacket =
      static_cast<PmidPacket*>(PacketFactory::Factory(PMID));
  // user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  PacketParams pmid_result = pmidPacket->Create(&user_params);

  std::string ser_packet =
      boost::any_cast<std::string>(pmid_result["ser_packet"]);
  GenericPacket generic_packet;
  generic_packet.ParseFromString(ser_packet);
  std::string signed_public_key = generic_packet.signature();

  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(pmid_result["name"]), ser_packet, PMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }

  printf("CCCCCCCCCCCCCC\n");
  ss_->AddKey(PMID, boost::any_cast<std::string>(pmid_result["name"]),
              boost::any_cast<std::string>(pmid_result["privateKey"]),
              boost::any_cast<std::string>(pmid_result["publicKey"]),
              signed_public_key);

  user_params["privateKey"] =
    createSignaturePackets(ANTMID, public_key);
  user_params["password"] = password;

  TmidPacket *tmidPacket =
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID));

  // STORING SERLIALISED DATA ATLAS
  std::string ser_da;
  ss_->SerialisedKeyRing(&ser_da);
  user_params["data"] = ser_da;
  PacketParams tmid_result = tmidPacket->Create(&user_params);
#ifdef DEBUG
  // printf("TMID %s\n", tmid_result);
#endif
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["ser_packet"]), TMID,
      PRIVATE, "") != kSuccess) {
    return kAuthenticationError;
  }

  printf("DDDDDDDDDDDDDDD\n");
  ss_->SetUsername(username);
  ss_->SetPin(pin);
  ss_->SetPassword(password);

  ss_->SetMidRid(boost::any_cast<uint32_t>(mid_result["rid"]));
  ss_->SetSmidRid(boost::any_cast<uint32_t>(mid_result["rid"]));

  delete check_unique_mid_packet;
  delete midPacket;
  delete smidPacket;
  delete tmidPacket;

  return kSuccess;
}

int Authentication::SaveSession(std::string ser_da,
                                PacketParams priv_keys,
                                PacketParams pub_keys) {
  PacketParams params;
  PacketParams result;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();
  std::string signed_public_key(""), signed_request("");

  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  MidPacket *midPacket =
    static_cast<MidPacket*>(PacketFactory::Factory(MID));
  TmidPacket *tmidPacket =
    static_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  SmidPacket *smidPacket =
    static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  if (ss_->MidRid() != ss_->SmidRid()) {
    params["rid"] = ss_->MidRid();
    params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANSMID"]);
    result = smidPacket->Create(&params);
    if (storemanager_->StorePacket(
        boost::any_cast<std::string>(result["name"]),
        boost::any_cast<std::string>(result["ser_packet"]), SMID, PRIVATE,
        "") != kSuccess) {
      return kAuthenticationError;
    }

    params["rid"] = ss_->SmidRid();
    std::string tmidname = tmidPacket->PacketName(&params);
    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                        boost::any_cast<std::string>(pub_keys["ANTMID"]),
                        tmidname,
                        &signed_public_key,
                        &signed_request);
//    AuthCallbackResult cb;
//    storemanager_->DeletePacket(tmidname, signed_request,
//        boost::any_cast<std::string>(pub_keys["ANTMID"]), signed_public_key,
//      SYSTEM_PACKET, boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//    WaitForResult(cb);
//    DeleteResponse del_res;
//    if ((!del_res.ParseFromString(cb.result)) ||
//      (del_res.result() == kNack)) {
//      return kAuthenticationError;
//    }
    ss_->SetSmidRid(ss_->MidRid());
  }

  params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANMID"]);
  PacketParams mid_result = midPacket->Create(&params);
  while (ss_->MidRid() == boost::any_cast<uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(&params);

  params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANTMID"]);
  params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  params["password"] = ss_->Password();
  params["data"] = ser_da;
  PacketParams tmidresult = tmidPacket->Create(&params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(tmidresult["name"]),
      boost::any_cast<std::string>(tmidresult["ser_packet"]), TMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }

  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["ser_packet"]), MID, PRIVATE,
      "") != 0) {
    return kAuthenticationError;
  }

  int temp = boost::any_cast<uint32_t>(mid_result["rid"]);
  ss_->SetMidRid(temp);
  delete midPacket;
  delete smidPacket;
  delete tmidPacket;
  return kSuccess;
}

int Authentication::RemoveMe(std::list<KeyAtlasRow> sig_keys) {
  MidPacket *midPacket =
    static_cast<MidPacket*>(PacketFactory::Factory(MID));
  SmidPacket *smidPacket =
    static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  TmidPacket *tmidPacket =
    static_cast<TmidPacket*>(PacketFactory::Factory(TMID));

  std::string signed_public_key(""), signed_request("");

  PacketParams params;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();

  AuthCallbackResult cb;

  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  params["rid"] = ss_->MidRid();
  std::string mpid_name = "";
  std::string pmid_name = "";

  while (!sig_keys.empty()) {
    AuthCallbackResult cbdel;
    KeyAtlasRow kt = sig_keys.front();
    sig_keys.pop_front();
    switch (kt.type_) {
      case ANMID:
          CreateSignedRequest(kt.private_key_,
                              kt.public_key_,
                              midPacket->PacketName(&params),
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(midPacket->PacketName(&params),
            signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          break;
      case ANSMID:signed_request =
          CreateSignedRequest(kt.private_key_,
                              kt.public_key_,
                              smidPacket->PacketName(&params),
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(smidPacket->PacketName(&params),
            signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          break;
      case ANTMID:
          CreateSignedRequest(kt.private_key_,
                              kt.public_key_,
                              tmidPacket->PacketName(&params),
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(tmidPacket->PacketName(&params),
            signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          params["rid"] = ss_->SmidRid();
          if (ss_->SmidRid() != ss_->MidRid()) {
            CreateSignedRequest(kt.private_key_,
                                kt.public_key_,
                                tmidPacket->PacketName(&params),
                                &signed_public_key,
                                &signed_request);
            cbdel.Reset();
            storemanager_->DeletePacket(tmidPacket->PacketName(&params),
              signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
              boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
            WaitForResult(cbdel);
          }
          break;
      case ANMPID:
          CreateSignedRequest(kt.private_key_,
                              kt.public_key_,
                              mpid_name,
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(mpid_name, signed_request,
            kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          break;
      case MAID:
          if (pmid_name != "") {
            CreateSignedRequest(kt.private_key_,
                                kt.public_key_,
                                pmid_name,
                                &signed_public_key,
                                &signed_request);
            cbdel.Reset();
            storemanager_->DeletePacket(pmid_name, signed_request,
              kt.public_key_, signed_public_key, SYSTEM_PACKET,
              boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
            WaitForResult(cbdel);
          }
          break;
      case MPID: mpid_name = kt.id_; break;
      case PMID: pmid_name = kt.id_; break;
    }
    CreateSignedRequest(kt.private_key_,
                        kt.public_key_,
                        kt.id_,
                        &signed_public_key,
                        &signed_request);
    cb.Reset();
    storemanager_->DeletePacket(kt.id_, signed_request, kt.public_key_,
      signed_public_key, SYSTEM_PACKET,
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
  }
  return kSuccess;
}

int Authentication::CreatePublicName(std::string public_username,
                                     PacketParams *result) {
  PacketParams params;
  PacketParams local_result;
  params["publicname"] = public_username;
  MpidPacket *mpidPacket =
    static_cast<MpidPacket*>(PacketFactory::Factory(MPID));
  std::string mpidname = mpidPacket->PacketName(&params);

  if (!storemanager_->KeyUnique(mpidname, false)) {
    printf("Authentication::CreatePublicName - Exists\n");
    return kPublicUsernameExists;
  }

  SignaturePacket *sigPacket =
    static_cast<SignaturePacket*>(PacketFactory::Factory(ANMPID));
  sigPacket->Create(&params);
  bool sigpacket_result = false;
  while (!sigpacket_result) {
    if (storemanager_->KeyUnique(boost::any_cast<std::string>(params["name"]),
        false)) {
      sigpacket_result = true;
    } else {
      sigPacket->Create(&params);
    }
  }

  ss_->AddKey(ANMPID, boost::any_cast<std::string>(params["name"]),
              boost::any_cast<std::string>(params["privateKey"]),
              boost::any_cast<std::string>(params["publicKey"]),
              "");
  if (storemanager_->StorePacket(boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["ser_packet"]), ANMPID, PRIVATE,
      "") != 0) {
    printf("Authentication::CreatePublicName - Buggered in ANMPID\n");
    delete mpidPacket;
    delete sigPacket;
    return kAuthenticationError;
  }
  local_result["anmpid_name"] = boost::any_cast<std::string>(params["name"]);
  local_result["anmpid_public_key"] = boost::any_cast<std::string>(
      params["publicKey"]);
  local_result["anmpid_private_key"] = boost::any_cast<std::string>(
      params["privateKey"]);

  PacketParams mpid_result = mpidPacket->Create(&params);
  std::string ser_packet =
      boost::any_cast<std::string>(mpid_result["ser_packet"]);
  GenericPacket generic_packet;
  generic_packet.ParseFromString(ser_packet);
  std::string signed_public_key = generic_packet.signature();

  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(mpid_result["name"]), ser_packet, MPID,
      PRIVATE, "") != 0) {
    printf("Authentication::CreatePublicName - Buggered in MPID\n");
    delete mpidPacket;
    delete sigPacket;
    return kAuthenticationError;
  }

  ss_->AddKey(MPID, public_username,
              boost::any_cast<std::string>(mpid_result["privateKey"]),
              boost::any_cast<std::string>(mpid_result["publicKey"]),
              signed_public_key);

  local_result["mpid_public_key"] = boost::any_cast<std::string>(
      mpid_result["publicKey"]);
  local_result["mpid_private_key"] = boost::any_cast<std::string>(
      mpid_result["privateKey"]);

  *result = local_result;
  delete mpidPacket;
  delete sigPacket;
  return kSuccess;
}

int Authentication::ChangeUsername(std::string ser_da,
                                   PacketParams priv_keys,
                                   PacketParams pub_keys,
                                   std::string new_username) {
  //   if (!CheckUsername(new_username) || new_username == ss_->Username())
  //     return INVALID_USERNAME;
  int fakerid;
  if (GetMid(new_username, ss_->Pin(), &fakerid))
    return kUserExists;

  MidPacket *midPacket =
    static_cast<MidPacket*>(PacketFactory::Factory(MID));
  PacketParams user_params;
  user_params["username"] = new_username;
  user_params["PIN"] = ss_->Pin();
  std::string mid_name = midPacket->PacketName(&user_params);
  AuthCallbackResult cb;
  std::string signed_public_key(""), signed_request("");

  //  Getting SMID Rid for current username
  SmidPacket *smidPacket =
    static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  //  Creating and storing new MID packet with new username
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANMID"]);
  PacketParams mid_result = midPacket->Create(&user_params);
  while (ss_->MidRid() == boost::any_cast<uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(&user_params);

  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["ser_packet"]), MID, PRIVATE,
      "") != 0) {
    return kAuthenticationError;
  }
  //  Creating and storing new SMID packet with new username and old MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANSMID"]);
  user_params["rid"] = ss_->MidRid();

  PacketParams smid_result = smidPacket->Create(&user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(smid_result["name"]),
      boost::any_cast<std::string>(smid_result["ser_packet"]), SMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }
  //  Creating new TMID-->MID with new MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANTMID"]);
  user_params["password"] = ss_->Password();
  user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  TmidPacket *tmidPacket =
    static_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  user_params["data"] = ser_da;
  PacketParams tmid_result = tmidPacket->Create(&user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["ser_packet"]), TMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }
  //  Creating new TMID-->SMID with old MID Rid and pointing to old DA
  PacketParams old_user_params;
  old_user_params["username"] = ss_->Username();
  old_user_params["PIN"] = ss_->Pin();
  old_user_params["rid"] = ss_->MidRid();

  std::string packet_content;
  int result = storemanager_->LoadPacket(tmidPacket->PacketName(
      &old_user_params), &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kAuthenticationError;
  std::string ser_tmid = packet_content;
  PacketParams rec_tmid = tmidPacket->GetData(ser_tmid, ss_->Password(),
    ss_->MidRid());
  std::string tmid_data = boost::any_cast<std::string>(rec_tmid["data"]);
  if (tmid_data == "")
    return kAuthenticationError;
  old_user_params["data"] = tmid_data;
  old_user_params["privateKey"] = boost::any_cast<std::string>(
      priv_keys["ANTMID"]);
  old_user_params["password"] = ss_->Password();
  old_user_params["username"] = new_username;
  tmid_result = tmidPacket->Create(&old_user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["ser_packet"]), TMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }
  user_params["username"] = ss_->Username();

//  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
//                      boost::any_cast<std::string>(pub_keys["ANMID"]),
//                      midPacket->PacketName(&user_params),
//                      &signed_public_key,
//                      &signed_request);
//  storemanager_->DeletePacket(midPacket->PacketName(&user_params),
//    signed_request, boost::any_cast<std::string>(pub_keys["ANMID"]),
//    signed_public_key, SYSTEM_PACKET,
//    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//  WaitForResult(cb);

//  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
//                      boost::any_cast<std::string>(pub_keys["ANSMID"]),
//                      smidPacket->PacketName(&user_params),
//                      &signed_public_key,
//                      &signed_request);
//  cb.Reset();
//  storemanager_->DeletePacket(smidPacket->PacketName(&user_params),
//    signed_request, boost::any_cast<std::string>(pub_keys["ANSMID"]),
//    signed_public_key, SYSTEM_PACKET,
//    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//  WaitForResult(cb);

//  user_params["rid"] = ss_->MidRid();
//
//  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
//                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
//                      tmidPacket->PacketName(&user_params),
//                      &signed_public_key,
//                      &signed_request);
//  cb.Reset();
//  storemanager_->DeletePacket(tmidPacket->PacketName(&user_params),
//    signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
//    signed_public_key, SYSTEM_PACKET,
//    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//  WaitForResult(cb);

//  if (ss_->MidRid() != ss_->SmidRid()) {
//    user_params["rid"] = ss_->SmidRid();
//    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
//                        boost::any_cast<std::string>(pub_keys["ANTMID"]),
//                        tmidPacket->PacketName(&user_params),
//                        &signed_public_key,
//                        &signed_request);
//    cb.Reset();
//    storemanager_->DeletePacket(tmidPacket->PacketName(&user_params),
//      signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
//      signed_public_key, SYSTEM_PACKET,
//      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//    WaitForResult(cb);
//  }

  ss_->SetUsername(new_username);
  ss_->SetSmidRid(ss_->MidRid());
  ss_->SetMidRid(boost::any_cast<uint32_t>(mid_result["rid"]));

  delete midPacket;
  delete smidPacket;
  delete tmidPacket;
  return kSuccess;
}

int Authentication::ChangePin(std::string ser_da,
                              PacketParams priv_keys,
                              PacketParams pub_keys,
                              std::string new_pin) {
  //   if (!CheckPin(new_pin) || new_pin == ss_->Pin())
  //     return INVALID_PIN;
  int fakerid;
  if (GetMid(ss_->Username(), new_pin, &fakerid))
    return kUserExists;

  MidPacket *midPacket =
    static_cast<MidPacket*>(PacketFactory::Factory(MID));
  PacketParams user_params;
  user_params["username"] = ss_->Username();
  user_params["PIN"] = new_pin;
  std::string mid_name = midPacket->PacketName(&user_params);

  AuthCallbackResult cb;
  std::string signed_public_key(""), signed_request("");

  //  Getting SMID Rid for current username
  SmidPacket *smidPacket =
    static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  if (ss_->SmidRid() == 0) {
    int smidrid;
    if (!GetSmid(ss_->Username(), ss_->Pin(), &smidrid)) {
      ss_->SetSmidRid(ss_->MidRid());
    } else {
      ss_->SetSmidRid(smidrid);
    }
  }

  //  Creating and storing new MID packet with new username
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANMID"]);
  PacketParams mid_result = midPacket->Create(&user_params);
  while (ss_->MidRid() == boost::any_cast<uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(&user_params);

  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["ser_packet"]), MID, PRIVATE,
      "") != 0) {
    return kAuthenticationError;
  }

  //  Creating and storing new SMID packet with new username and old MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANSMID"]);
  user_params["rid"] = ss_->MidRid();

  PacketParams smid_result = smidPacket->Create(&user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(smid_result["name"]),
      boost::any_cast<std::string>(smid_result["ser_packet"]), SMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }

  //  Creating new TMID-->MID with new MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANTMID"]);
  user_params["password"] = ss_->Password();
  user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  TmidPacket *tmidPacket =
    static_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  user_params["data"] = ser_da;
  PacketParams tmid_result = tmidPacket->Create(&user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["ser_packet"]), TMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }

  //  Creating new TMID-->SMID with old MID Rid and pointing to old DA
  PacketParams old_user_params;
  old_user_params["username"] = ss_->Username();
  old_user_params["PIN"] = ss_->Pin();
  old_user_params["rid"] = ss_->MidRid();

  std::string packet_content;
  int result = storemanager_->LoadPacket(tmidPacket->PacketName(
      &old_user_params), &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kAuthenticationError;
  std::string ser_tmid = packet_content;
  PacketParams rec_data = tmidPacket->GetData(ser_tmid,
    ss_->Password(), ss_->MidRid());
  std::string tmid_data = boost::any_cast<std::string>(rec_data["data"]);
  if (tmid_data == "")
    return kAuthenticationError;
  old_user_params["data"] = tmid_data;
  old_user_params["privateKey"] = boost::any_cast<std::string>(
      priv_keys["ANTMID"]);
  old_user_params["password"] = ss_->Password();
  old_user_params["PIN"] = new_pin;
  tmid_result = tmidPacket->Create(&old_user_params);
  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(tmid_result["name"]),
      boost::any_cast<std::string>(tmid_result["ser_packet"]), TMID,
      PRIVATE, "") != 0) {
    return kAuthenticationError;
  }

//  user_params["PIN"] = ss_->Pin();

//  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
//                      boost::any_cast<std::string>(pub_keys["ANMID"]),
//                      midPacket->PacketName(&user_params),
//                      &signed_public_key,
//                      &signed_request);
//  cb.Reset();
//  storemanager_->DeletePacket(midPacket->PacketName(&user_params),
//    signed_request, boost::any_cast<std::string>(pub_keys["ANMID"]),
//    signed_public_key, SYSTEM_PACKET,
//    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//  WaitForResult(cb);

//  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
//                      boost::any_cast<std::string>(pub_keys["ANSMID"]),
//                      smidPacket->PacketName(&user_params),
//                      &signed_public_key,
//                      &signed_request);
//  cb.Reset();
//  storemanager_->DeletePacket(smidPacket->PacketName(&user_params),
//    signed_request, boost::any_cast<std::string>(pub_keys["ANSMID"]),
//    signed_public_key, SYSTEM_PACKET,
//    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//  WaitForResult(cb);

//  user_params["rid"] = ss_->MidRid();
//  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
//                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
//                      tmidPacket->PacketName(&user_params),
//                      &signed_public_key,
//                      &signed_request);
//  cb.Reset();
//  storemanager_->DeletePacket(tmidPacket->PacketName(&user_params),
//    signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
//    signed_public_key, SYSTEM_PACKET,
//    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//  WaitForResult(cb);


//  if (ss_->MidRid() != ss_->SmidRid()) {
//    user_params["rid"] = ss_->SmidRid();
//    AuthCallbackResult cb3;
//    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
//                        boost::any_cast<std::string>(pub_keys["ANTMID"]),
//                        tmidPacket->PacketName(&user_params),
//                        &signed_public_key,
//                        &signed_request);
//    cb.Reset();
//    storemanager_->DeletePacket(tmidPacket->PacketName(&user_params),
//      signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
//      signed_public_key, SYSTEM_PACKET,
//      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
//    WaitForResult(cb);
//  }

  ss_->SetPin(new_pin);
  ss_->SetSmidRid(ss_->MidRid());
  ss_->SetMidRid(boost::any_cast<uint32_t>(mid_result["rid"]));
  delete midPacket;
  delete smidPacket;
  delete tmidPacket;

  return kSuccess;
}

int Authentication::ChangePassword(std::string ser_da,
                                   PacketParams priv_keys,
                                   PacketParams pub_keys,
                                   std::string new_password) {
  //   if (!CheckPassword(new_password) || new_password == ss_->Password())
  //     return INVALID_PASSWORD;
  std::string old_password = ss_->Password();
  ss_->SetPassword(new_password);
  if (SaveSession(ser_da, priv_keys, pub_keys) == kSuccess) {
    return kSuccess;
  } else {
    ss_->SetPassword(old_password);
    return kAuthenticationError;
  }
}

std::string Authentication::createSignaturePackets(const PacketType &type_da,
                                                   std::string &public_key) {
  PacketParams params;
  SignaturePacket *sigPacket =
      static_cast<SignaturePacket*>(PacketFactory::Factory(type_da));
  sigPacket->Create(&params);

  AuthCallbackResult cb;
  bool result = false;
  while (!result) {
    if (storemanager_->KeyUnique(boost::any_cast<std::string>(params["name"]),
        false)) {
      result = true;
    } else {
      sigPacket->Create(&params);
    }
  }
  ss_->AddKey(type_da, boost::any_cast<std::string>(params["name"]),
              boost::any_cast<std::string>(params["privateKey"]),
              boost::any_cast<std::string>(params["publicKey"]), "");

  if (storemanager_->StorePacket(
      boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["ser_packet"]), type_da, PRIVATE, "")
      != 0) {
    return "";
  }

  public_key = boost::any_cast<std::string>(params["publicKey"]);
  delete sigPacket;
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

int Authentication::CreateSignedRequest(const std::string &private_key,
                                        const std::string &public_key,
                                        const std::string &hex_packet_name,
                                        std::string *signed_public_key,
                                        std::string *signed_request) {
  crypto::Crypto cry_obj_;
  cry_obj_.set_symm_algorithm(crypto::AES_256);
  cry_obj_.set_hash_algorithm(crypto::SHA_512);
  *signed_public_key = cry_obj_.AsymSign(public_key,
                                         "",
                                         private_key,
                                         crypto::STRING_STRING);
  *signed_request = cry_obj_.AsymSign(
      cry_obj_.Hash(public_key + *signed_public_key +
                    base::DecodeFromHex(hex_packet_name),
                        "",
                        crypto::STRING_STRING,
                        false),
      "",
      private_key,
      crypto::STRING_STRING);
  return 0;
}

void Authentication::WaitForResult(const AuthCallbackResult &cb) {
  while (true) {
    {
      boost::mutex::scoped_lock gaurd(mutex_);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
}

bool Authentication::GetMid(const std::string &username,
                            const std::string &pin,
                            int *rid) {
  PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  MidPacket *midPacket = static_cast<MidPacket*>
    (PacketFactory::Factory(MID));
  std::string mid_name = midPacket->PacketName(&params);

  std::string ser_packet;
  std::string packet_content;
  int result = storemanager_->LoadPacket(mid_name, &packet_content);
  if (result != kSuccess || packet_content.empty()) {
    delete midPacket;
    return false;
  }
  ser_packet = packet_content;
  PacketParams info = midPacket->GetData(ser_packet, username, pin);
  // The key of mid_name clashed with another value that is not a mid
  // hence, it could not recover a valid mid but we can not return false
  // because that would mean it doesn't exist
  uint32_t rec_data = boost::any_cast<uint32_t>(info["data"]);
  if (rec_data == 0) {
    delete midPacket;
    *rid = 0;
    return true;
  }
  *rid = rec_data;
  delete midPacket;
  return true;
}

bool Authentication::GetSmid(const std::string &username,
                             const std::string &pin,
                             int *rid) {
  PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  SmidPacket *smidPacket = static_cast<SmidPacket*>
    (PacketFactory::Factory(SMID));
  std::string smid_name = smidPacket->PacketName(&params);
  std::string ser_packet;
  std::string packet_content;
  int result = storemanager_->LoadPacket(smid_name, &packet_content);
  if (result != kSuccess || packet_content.empty()) {
    delete smidPacket;
    return false;
  }
  ser_packet = packet_content;
  PacketParams info = smidPacket->GetData(ser_packet, username, pin);
  uint32_t rec_data = boost::any_cast<uint32_t>(info["data"]);
  if (rec_data != 0) {
    // The key of mid_name clashed with another value that is not a smid
    // hence, it could not recovder a valid smid but we can not return false
    // because that would mean it doesn't exists
    *rid = 0;
    delete smidPacket;
    return false;
  }
  *rid = rec_data;
  delete smidPacket;
  return true;
}

void Authentication::GetUserTmid(bool smid) {
  TmidPacket *tmidPacket = static_cast<TmidPacket*>(
                               PacketFactory::Factory(TMID));
  PacketParams params;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();
  params["rid"] = ss_->MidRid();
  std::string tmid_name = tmidPacket->PacketName(&params);
  std::string packet_content;
  int result = storemanager_->LoadPacket(tmid_name, &packet_content);
// #ifdef DEBUG
//    if (!load_res.ParseFromString(packet_content))
//      printf("Authentication::GetUserTmid - Doesn't parse as GetUserTmid.\n");
//    if (load_res.result() != kAck)
//      printf("Authentication::GetUserTmid - came back with failure.\n");
//    if (!load_res.has_content())
//      printf("Authentication::GetUserTmid - came back with no content.\n");
// #endif
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
  tmid_content_ = packet_content;
#ifdef DEBUG
  printf("Authentication::GetUserTmidCallback returning content result\n");
#endif
}

int Authentication::PublicUsernamePublicKey(const std::string &public_username,
                                            std::string &public_key) {
  PacketParams params;
  params["publicname"] = public_username;
  MpidPacket *mpidPacket =
    static_cast<MpidPacket*>(PacketFactory::Factory(MPID));

  std::string packet_content;
  int result = storemanager_->LoadPacket(mpidPacket->PacketName(&params),
                                         &packet_content);
  if (result != kSuccess || packet_content.empty())
    return kUserDoesntExist;
  std::string ser_generic_packet = packet_content;
  GenericPacket gp;
  if (!gp.ParseFromString(ser_generic_packet)) {
    return kAuthenticationError;  //  Packet corrupt
  }

  public_key = gp.data();

  return kSuccess;
}

void Authentication::CreateMSIDPacket(base::callback_func_type cb) {
  PacketParams params;
  SignaturePacket *sigPacket = static_cast<SignaturePacket*>(
                               PacketFactory::Factory(MSID));
  sigPacket->Create(&params);

  int count = 0;
  while (!storemanager_->KeyUnique(boost::any_cast<std::string>(params["name"]),
      false) && count < 10)
    ++count;

  if (count == 10) {
    CreateMSIDResult local_result;
    local_result.set_result(kNack);
    std::string ser_local_result;
    local_result.SerializeToString(&ser_local_result);
    cb(ser_local_result);
    return;
  }

  int n = storemanager_->StorePacket(
      boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["ser_packet"]), MSID, PRIVATE,
      "");
  StoreResponse result_msg;
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

}  // namespace maidsafe
