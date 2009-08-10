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
#include <cstdio>

#include "maidsafe/maidsafe.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe {

AuthCallbackResult::AuthCallbackResult() :result("") {}

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

Authentication::Authentication(StoreManagerInterface *storemanager,
                               boost::recursive_mutex *mutex)
                                   : ud_(),
                                     mutex_(mutex),
                                     crypto_(),
                                     storemanager_(storemanager),
                                     ss_(SessionSingleton::getInstance()),
                                     tmid_content() {
  ss_->ResetSession();
  crypto_.set_hash_algorithm(crypto::SHA_512);
  crypto_.set_symm_algorithm(crypto::AES_256);
}

Exitcode Authentication::GetUserInfo(const std::string &username,
                                     const std::string &pin,
                                     base::callback_func_type cb) {
  ss_->SetSmidRid(0);
  tmid_content = "";
  int rid = 0;
  bool smid = false;
  if (!GetMid(username, pin, &rid)) {
    if (!GetSmid(username, pin, &rid)) {
      ss_->ResetSession();
      return NON_EXISTING_USER;
    }
    ss_->SetSmidRid(rid);
    smid = true;
  }
  if (rid == 0) {
    ss_->ResetSession();
    return INVALID_USERNAME_PIN;
  }
  ss_->SetMidRid(rid);
  ss_->SetUsername(username);
  ss_->SetPin(pin);
  // Getting tmid
  GetUserTmid(cb, smid);

  return USER_EXISTS;
}

Exitcode Authentication::GetUserData(const std::string &password,
                                     std::string &ser_da) {
  //  still have not recovered the tmid
  if (tmid_content == "")
    return PASSWORD_FAIL;
  ph::TmidPacket *tmidPacket =
    static_cast<ph::TmidPacket*>(ph::PacketFactory::Factory(ph::TMID));
  ph::PacketParams rec_data = tmidPacket->GetData(tmid_content, password,
      ss_->MidRid());
  ser_da = boost::any_cast<std::string>(rec_data["data"]);

  DataAtlas da;
  if (!da.ParseFromString(ser_da))
    return PASSWORD_FAIL;
  ss_->SetPassword(password);
  return OK;
}

Exitcode Authentication::CreateUserSysPackets(const std::string &username,
                                              const std::string &pin,
                                              const std::string &password) {
  int fakerid = 0;
  if (GetMid(username, pin, &fakerid))
    return USER_EXISTS;
  ph::MidPacket *midPacket =
      static_cast<ph::MidPacket*>(ph::PacketFactory::Factory(ph::MID));
  ph::PacketParams user_params;
  user_params["username"] = username;
  user_params["PIN"] = pin;
  DataAtlas data_atlas;
  std::string public_key;

  user_params["privateKey"] =
      createSignaturePackets(ph::ANMID, ANMID, public_key);
  ph::PacketParams mid_result = midPacket->Create(user_params);
  std::string signed_public_key(""), signed_request("");
  CreateSignedRequest(boost::any_cast<std::string>(user_params["privateKey"]),
                      public_key,
                      boost::any_cast<std::string>(mid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  AuthCallbackResult cb;
  storemanager_->StorePacket(boost::any_cast<std::string>(mid_result["name"]),
    boost::any_cast<std::string>(mid_result["ser_packet"]),
    signed_request, public_key, signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  StoreResponse store_res;
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
    return FAIL;
  }

  user_params["privateKey"] =
      createSignaturePackets(ph::ANSMID, ANSMID, public_key);
  ph::SmidPacket *smidPacket =
      static_cast<ph::SmidPacket*>(ph::PacketFactory::Factory(ph::SMID));
  user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  ph::PacketParams smid_result = smidPacket->Create(user_params);
  CreateSignedRequest(boost::any_cast<std::string>(user_params["privateKey"]),
                      public_key,
                      boost::any_cast<std::string>(smid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  store_res.Clear();
  storemanager_->StorePacket(boost::any_cast<std::string>(smid_result["name"]),
    boost::any_cast<std::string>(smid_result["ser_packet"]),
    signed_request, public_key, signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
    return FAIL;
  }

  std::string privkey = createSignaturePackets(ph::MAID, MAID, public_key);

  // user_params["privateKey"] =
  //  createSignaturePackets(ph::PMID, PMID, data_atlas, public_key);
  user_params["privateKey"] = privkey;
  ph::PmidPacket *pmidPacket =
      static_cast<ph::PmidPacket*>(ph::PacketFactory::Factory(ph::PMID));
  // user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  ph::PacketParams pmid_result = pmidPacket->Create(user_params);

  CreateSignedRequest(boost::any_cast<std::string>(user_params["privateKey"]),
                      public_key,
                      boost::any_cast<std::string>(pmid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  store_res.Clear();
  storemanager_->StorePacket(boost::any_cast<std::string>(pmid_result["name"]),
    boost::any_cast<std::string>(pmid_result["ser_packet"]),
    signed_request, public_key, signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
    return FAIL;
  }

  ss_->AddKey(PMID, boost::any_cast<std::string>(pmid_result["name"]),
              boost::any_cast<std::string>(pmid_result["privateKey"]),
              boost::any_cast<std::string>(pmid_result["publicKey"]));

  user_params["privateKey"] =
    createSignaturePackets(ph::ANTMID, ANTMID, public_key);
  user_params["password"] = password;


  ph::TmidPacket *tmidPacket =
      static_cast<ph::TmidPacket*>(ph::PacketFactory::Factory(ph::TMID));

  // STORING SERLIALISED DATA ATLAS
  std::string ser_da;
  ss_->SerialisedKeyRing(&ser_da);
  user_params["data"] = ser_da;
  ph::PacketParams tmid_result = tmidPacket->Create(user_params);
#ifdef DEBUG
  // printf("TMID %s\n", tmid_result);
#endif
  CreateSignedRequest(boost::any_cast<std::string>(user_params["privateKey"]),
                      public_key,
                      boost::any_cast<std::string>(tmid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  store_res.Clear();
  storemanager_->StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
    boost::any_cast<std::string>(tmid_result["ser_packet"]),
    signed_request, public_key, signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
    return FAIL;
  }

  ss_->SetUsername(username);
  ss_->SetPin(pin);
  ss_->SetPassword(password);

  ss_->SetMidRid(boost::any_cast<uint32_t>(mid_result["rid"]));
  ss_->SetSmidRid(boost::any_cast<uint32_t>(mid_result["rid"]));

  delete midPacket;
  delete smidPacket;
  delete tmidPacket;

  return OK;
}

Exitcode Authentication::SaveSession(std::string ser_da,
                                     ph::PacketParams priv_keys,
                                     ph::PacketParams pub_keys) {
  ph::PacketParams params;
  ph::PacketParams result;
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

  ph::MidPacket *midPacket =
    static_cast<ph::MidPacket*>(ph::PacketFactory::Factory(ph::MID));
  ph::TmidPacket *tmidPacket =
    static_cast<ph::TmidPacket*>(ph::PacketFactory::Factory(ph::TMID));
  ph::SmidPacket *smidPacket =
    static_cast<ph::SmidPacket*>(ph::PacketFactory::Factory(ph::SMID));
  AuthCallbackResult cb;
  StoreResponse store_res;
  if (ss_->MidRid() != ss_->SmidRid()) {
    params["rid"] = ss_->MidRid();
    params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANSMID"]);
    result = smidPacket->Create(params);
    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
                        boost::any_cast<std::string>(pub_keys["ANSMID"]),
                        boost::any_cast<std::string>(result["name"]),
                        &signed_public_key,
                        &signed_request);
    cb.Reset();
    storemanager_->StorePacket(boost::any_cast<std::string>(result["name"]),
        boost::any_cast<std::string>(result["ser_packet"]), signed_request,
        boost::any_cast<std::string>(pub_keys["ANSMID"]),
        signed_public_key, SYSTEM_PACKET, true,
        boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
    if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
      return FAIL;
    }

    params["rid"] = ss_->SmidRid();
    std::string tmidname = tmidPacket->PacketName(params);
    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                        boost::any_cast<std::string>(pub_keys["ANTMID"]),
                        tmidname,
                        &signed_public_key,
                        &signed_request);
    cb.Reset();
    store_res.Clear();
    storemanager_->DeletePacket(tmidname, signed_request,
        boost::any_cast<std::string>(pub_keys["ANTMID"]), signed_public_key,
        SYSTEM_PACKET, boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
    DeleteResponse del_res;
    if ((!del_res.ParseFromString(cb.result)) ||
      (del_res.result() == kNack)) {
      return FAIL;
    }

    ss_->SetSmidRid(ss_->MidRid());
  }

  params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANMID"]);
  ph::PacketParams mid_result = midPacket->Create(params);
  while (ss_->MidRid() == boost::any_cast<uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(params);

  params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANTMID"]);
  params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  params["password"] = ss_->Password();
  params["data"] = ser_da;
  ph::PacketParams tmidresult = tmidPacket->Create(params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      boost::any_cast<std::string>(tmidresult["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  store_res.Clear();
  storemanager_->StorePacket(boost::any_cast<std::string>(tmidresult["name"]),
      boost::any_cast<std::string>(tmidresult["ser_packet"]),
      signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
      signed_public_key, SYSTEM_PACKET, false,
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
    return FAIL;
  }

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
                      boost::any_cast<std::string>(pub_keys["ANMID"]),
                      boost::any_cast<std::string>(mid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  store_res.Clear();
  storemanager_->StorePacket(boost::any_cast<std::string>(mid_result["name"]),
      boost::any_cast<std::string>(mid_result["ser_packet"]), signed_request,
      boost::any_cast<std::string>(pub_keys["ANMID"]),
      signed_public_key, SYSTEM_PACKET, true,
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack)) {
    return FAIL;
  }

  int temp = boost::any_cast<uint32_t>(mid_result["rid"]);
  ss_->SetMidRid(temp);
  delete midPacket;
  delete smidPacket;
  delete tmidPacket;
  return OK;
}

Exitcode Authentication::RemoveMe(std::list<KeyAtlasRow> sig_keys) {
  ph::MidPacket *midPacket =
    static_cast<ph::MidPacket*>(ph::PacketFactory::Factory(ph::MID));
  ph::SmidPacket *smidPacket =
    static_cast<ph::SmidPacket*>(ph::PacketFactory::Factory(ph::SMID));
  ph::TmidPacket *tmidPacket =
    static_cast<ph::TmidPacket*>(ph::PacketFactory::Factory(ph::TMID));

  std::string signed_public_key(""), signed_request("");

  ph::PacketParams params;
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
                              midPacket->PacketName(params),
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(midPacket->PacketName(params),
            signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          break;
      case ANSMID:signed_request =
          CreateSignedRequest(kt.private_key_,
                              kt.public_key_,
                              smidPacket->PacketName(params),
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(smidPacket->PacketName(params),
            signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          break;
      case ANTMID:
          CreateSignedRequest(kt.private_key_,
                              kt.public_key_,
                              tmidPacket->PacketName(params),
                              &signed_public_key,
                              &signed_request);
          cbdel.Reset();
          storemanager_->DeletePacket(tmidPacket->PacketName(params),
            signed_request, kt.public_key_, signed_public_key, SYSTEM_PACKET,
            boost::bind(&AuthCallbackResult::CallbackFunc, &cbdel, _1));
          WaitForResult(cbdel);
          params["rid"] = ss_->SmidRid();
          if (ss_->SmidRid() != ss_->MidRid()) {
            CreateSignedRequest(kt.private_key_,
                                kt.public_key_,
                                tmidPacket->PacketName(params),
                                &signed_public_key,
                                &signed_request);
            cbdel.Reset();
            storemanager_->DeletePacket(tmidPacket->PacketName(params),
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
  return OK;
}

Exitcode Authentication::CreatePublicName(std::string public_username,
                                          ph::PacketParams *result) {
  ph::PacketParams params;
  ph::PacketParams local_result;
  params["publicname"] = public_username;
  ph::MpidPacket *mpidPacket =
    static_cast<ph::MpidPacket*>(ph::PacketFactory::Factory(ph::MPID));
  std::string mpidname = mpidPacket->PacketName(params);
  std::string signed_public_key;
  std::string signed_request;

  AuthCallbackResult cb;
  storemanager_->IsKeyUnique(mpidname,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GenericResponse is_unique_res;
  is_unique_res.ParseFromString(cb.result);
  if (is_unique_res.result() == kNack)
    return PUBLIC_USERNAME_EXISTS;
  is_unique_res.Clear();

  ph::SignaturePacket *sigPacket =
    static_cast<ph::SignaturePacket*>(ph::PacketFactory::Factory(ph::ANMPID));
  params = sigPacket->Create(params);
  bool sigpacket_result = false;
  while (!sigpacket_result) {
    cb.Reset();
    storemanager_->IsKeyUnique(boost::any_cast<std::string>(params["name"]),
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
    is_unique_res.ParseFromString(cb.result);
    if (is_unique_res.result() == kAck)
      sigpacket_result = true;
    else
      params = sigPacket->Create(params);
  }

  CreateSignedRequest(boost::any_cast<std::string>(params["privateKey"]),
                      boost::any_cast<std::string>(params["publicKey"]),
                      boost::any_cast<std::string>(params["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(params["name"]),
    boost::any_cast<std::string>(params["ser_packet"]), signed_request,
    boost::any_cast<std::string>(params["publicKey"]), signed_public_key,
    SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  StoreResponse store_res;
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();
  local_result["anmpid_name"] = boost::any_cast<std::string>(params["name"]);
  local_result["anmpid_public_key"] = boost::any_cast<std::string>(
      params["publicKey"]);
  local_result["anmpid_private_key"] = boost::any_cast<std::string>(
      params["privateKey"]);

  ph::PacketParams mpid_result = mpidPacket->Create(params);

  CreateSignedRequest(boost::any_cast<std::string>(params["privateKey"]),
                      boost::any_cast<std::string>(params["publicKey"]),
                      boost::any_cast<std::string>(mpid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(mpid_result["name"]),
    boost::any_cast<std::string>(mpid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(params["publicKey"]), signed_public_key,
    SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
    if ((!store_res.ParseFromString(cb.result)) ||
        (store_res.result() == kNack))
    return FAIL;
  local_result["mpid_public_key"] = boost::any_cast<std::string>(
      mpid_result["publicKey"]);
  local_result["mpid_private_key"] = boost::any_cast<std::string>(
      mpid_result["privateKey"]);

  *result = local_result;
  delete mpidPacket;
  delete sigPacket;
  return OK;
}

Exitcode Authentication::ChangeUsername(std::string ser_da,
                                        ph::PacketParams priv_keys,
                                        ph::PacketParams pub_keys,
                                        std::string new_username) {
  //   if (!CheckUsername(new_username) || new_username == ss_->Username())
  //     return INVALID_USERNAME;
  int fakerid;
  if (GetMid(new_username, ss_->Pin(), &fakerid))
    return USER_EXISTS;

  ph::MidPacket *midPacket =
    static_cast<ph::MidPacket*>(ph::PacketFactory::Factory(ph::MID));
  ph::PacketParams user_params;
  user_params["username"] = new_username;
  user_params["PIN"] = ss_->Pin();
  std::string mid_name = midPacket->PacketName(user_params);
  AuthCallbackResult cb;
  std::string signed_public_key(""), signed_request("");

  //  Getting SMID Rid for current username
  ph::SmidPacket *smidPacket =
    static_cast<ph::SmidPacket*>(ph::PacketFactory::Factory(ph::SMID));
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
  ph::PacketParams mid_result = midPacket->Create(user_params);
  while (ss_->MidRid() == boost::any_cast<uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(user_params);

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
                      boost::any_cast<std::string>(pub_keys["ANMID"]),
                      boost::any_cast<std::string>(mid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(mid_result["name"]),
    boost::any_cast<std::string>(mid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  StoreResponse store_res;
  if ((!store_res.ParseFromString(cb.result)) ||
    (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();

  //  Creating and storing new SMID packet with new username and old MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANSMID"]);
  user_params["rid"] = ss_->MidRid();

  ph::PacketParams smid_result = smidPacket->Create(user_params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
                      boost::any_cast<std::string>(pub_keys["ANSMID"]),
                      boost::any_cast<std::string>(smid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(smid_result["name"]),
    boost::any_cast<std::string>(smid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANSMID"]), signed_public_key,
    SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
    (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();
  //  Creating new TMID-->MID with new MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANTMID"]);
  user_params["password"] = ss_->Password();
  user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  ph::TmidPacket *tmidPacket =
    static_cast<ph::TmidPacket*>(ph::PacketFactory::Factory(ph::TMID));
  user_params["data"] = ser_da;
  ph::PacketParams tmid_result = tmidPacket->Create(user_params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      boost::any_cast<std::string>(tmid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
    boost::any_cast<std::string>(tmid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANTMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
    (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();
  //  Creating new TMID-->SMID with old MID Rid and pointing to old DA
  ph::PacketParams old_user_params;
  old_user_params["username"] = ss_->Username();
  old_user_params["PIN"] = ss_->Pin();
  old_user_params["rid"] = ss_->MidRid();

  cb.Reset();
  storemanager_->LoadPacket(tmidPacket->PacketName(old_user_params),
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GetResponse load_res;
  if ((!load_res.ParseFromString(cb.result)) ||
      (load_res.result() == kNack) ||
      (!load_res.has_content()))
    return FAIL;
  std::string ser_tmid = load_res.content();
  ph::PacketParams rec_tmid = tmidPacket->GetData(ser_tmid, ss_->Password(),
    ss_->MidRid());
  std::string tmid_data = boost::any_cast<std::string>(rec_tmid["data"]);
  if (tmid_data == "")
    return FAIL;
  old_user_params["data"] = tmid_data;
  old_user_params["privateKey"] = boost::any_cast<std::string>(
      priv_keys["ANTMID"]);
  old_user_params["password"] = ss_->Password();
  old_user_params["username"] = new_username;
  tmid_result = tmidPacket->Create(old_user_params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      boost::any_cast<std::string>(tmid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
    boost::any_cast<std::string>(tmid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANTMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack))
    return FAIL;

  user_params["username"] = ss_->Username();

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
                      boost::any_cast<std::string>(pub_keys["ANMID"]),
                      midPacket->PacketName(user_params),
                      &signed_public_key,
                      &signed_request);
  storemanager_->DeletePacket(midPacket->PacketName(user_params),
    signed_request, boost::any_cast<std::string>(pub_keys["ANMID"]),
    signed_public_key, SYSTEM_PACKET,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
                      boost::any_cast<std::string>(pub_keys["ANSMID"]),
                      smidPacket->PacketName(user_params),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->DeletePacket(smidPacket->PacketName(user_params),
    signed_request, boost::any_cast<std::string>(pub_keys["ANSMID"]),
    signed_public_key, SYSTEM_PACKET,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  user_params["rid"] = ss_->MidRid();

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      tmidPacket->PacketName(user_params),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->DeletePacket(tmidPacket->PacketName(user_params),
    signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
    signed_public_key, SYSTEM_PACKET,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  if (ss_->MidRid() != ss_->SmidRid()) {
    user_params["rid"] = ss_->SmidRid();
    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                        boost::any_cast<std::string>(pub_keys["ANTMID"]),
                        tmidPacket->PacketName(user_params),
                        &signed_public_key,
                        &signed_request);
    cb.Reset();
    storemanager_->DeletePacket(tmidPacket->PacketName(user_params),
      signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
      signed_public_key, SYSTEM_PACKET,
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
  }

  ss_->SetUsername(new_username);
  ss_->SetSmidRid(ss_->MidRid());
  ss_->SetMidRid(boost::any_cast<uint32_t>(mid_result["rid"]));

  delete midPacket;
  delete smidPacket;
  delete tmidPacket;
  return OK;
}

Exitcode Authentication::ChangePin(std::string ser_da,
                                   ph::PacketParams priv_keys,
                                   ph::PacketParams pub_keys,
                                   std::string new_pin) {
  //   if (!CheckPin(new_pin) || new_pin == ss_->Pin())
  //     return INVALID_PIN;
  int fakerid;
  if (GetMid(ss_->Username(), new_pin, &fakerid))
    return USER_EXISTS;

  ph::MidPacket *midPacket =
    static_cast<ph::MidPacket*>(ph::PacketFactory::Factory(ph::MID));
  ph::PacketParams user_params;
  user_params["username"] = ss_->Username();
  user_params["PIN"] = new_pin;
  std::string mid_name = midPacket->PacketName(user_params);

  AuthCallbackResult cb;
  std::string signed_public_key(""), signed_request("");

  //  Getting SMID Rid for current username
  ph::SmidPacket *smidPacket =
    static_cast<ph::SmidPacket*>(ph::PacketFactory::Factory(ph::SMID));
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
  ph::PacketParams mid_result = midPacket->Create(user_params);
  while (ss_->MidRid() == boost::any_cast<uint32_t>(mid_result["rid"]))
    mid_result = midPacket->Create(user_params);

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
                      boost::any_cast<std::string>(pub_keys["ANMID"]),
                      boost::any_cast<std::string>(mid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(mid_result["name"]),
    boost::any_cast<std::string>(mid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  StoreResponse store_res;
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();

  //  Creating and storing new SMID packet with new username and old MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANSMID"]);
  user_params["rid"] = ss_->MidRid();

  ph::PacketParams smid_result = smidPacket->Create(user_params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
                      boost::any_cast<std::string>(pub_keys["ANSMID"]),
                      boost::any_cast<std::string>(smid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(smid_result["name"]),
    boost::any_cast<std::string>(smid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANSMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();

  //  Creating new TMID-->MID with new MID Rid
  user_params["privateKey"] = boost::any_cast<std::string>(priv_keys["ANTMID"]);
  user_params["password"] = ss_->Password();
  user_params["rid"] = boost::any_cast<uint32_t>(mid_result["rid"]);
  ph::TmidPacket *tmidPacket =
    static_cast<ph::TmidPacket*>(ph::PacketFactory::Factory(ph::TMID));
  user_params["data"] = ser_da;
  ph::PacketParams tmid_result = tmidPacket->Create(user_params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      boost::any_cast<std::string>(tmid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
    boost::any_cast<std::string>(tmid_result["ser_packet"]), signed_request,
    boost::any_cast<std::string>(pub_keys["ANTMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();

  //  Creating new TMID-->SMID with old MID Rid and pointing to old DA
  ph::PacketParams old_user_params;
  old_user_params["username"] = ss_->Username();
  old_user_params["PIN"] = ss_->Pin();
  old_user_params["rid"] = ss_->MidRid();

  cb.Reset();
  storemanager_->LoadPacket(tmidPacket->PacketName(old_user_params),
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GetResponse load_res;
  if ((!load_res.ParseFromString(cb.result)) ||
      (load_res.result() != kAck) ||
      (!load_res.has_content()))
    return FAIL;
  std::string ser_tmid = load_res.content();
  ph::PacketParams rec_data = tmidPacket->GetData(ser_tmid,
    ss_->Password(), ss_->MidRid());
  std::string tmid_data = boost::any_cast<std::string>(rec_data["data"]);
  if (tmid_data == "")
    return FAIL;
  old_user_params["data"] = tmid_data;
  old_user_params["privateKey"] = boost::any_cast<std::string>(
      priv_keys["ANTMID"]);
  old_user_params["password"] = ss_->Password();
  old_user_params["PIN"] = new_pin;
  tmid_result = tmidPacket->Create(old_user_params);
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      boost::any_cast<std::string>(tmid_result["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(tmid_result["name"]),
    boost::any_cast<std::string>(tmid_result["ser_packet"]),
    signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kNack))
    return FAIL;
  store_res.Clear();

  user_params["PIN"] = ss_->Pin();

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANMID"]),
                      boost::any_cast<std::string>(pub_keys["ANMID"]),
                      midPacket->PacketName(user_params),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->DeletePacket(midPacket->PacketName(user_params),
    signed_request, boost::any_cast<std::string>(pub_keys["ANMID"]),
    signed_public_key, SYSTEM_PACKET,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANSMID"]),
                      boost::any_cast<std::string>(pub_keys["ANSMID"]),
                      smidPacket->PacketName(user_params),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->DeletePacket(smidPacket->PacketName(user_params),
    signed_request, boost::any_cast<std::string>(pub_keys["ANSMID"]),
    signed_public_key, SYSTEM_PACKET,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  user_params["rid"] = ss_->MidRid();
  CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                      boost::any_cast<std::string>(pub_keys["ANTMID"]),
                      tmidPacket->PacketName(user_params),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->DeletePacket(tmidPacket->PacketName(user_params),
    signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
    signed_public_key, SYSTEM_PACKET,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);


  if (ss_->MidRid() != ss_->SmidRid()) {
    user_params["rid"] = ss_->SmidRid();
    AuthCallbackResult cb3;
    CreateSignedRequest(boost::any_cast<std::string>(priv_keys["ANTMID"]),
                        boost::any_cast<std::string>(pub_keys["ANTMID"]),
                        tmidPacket->PacketName(user_params),
                        &signed_public_key,
                        &signed_request);
    cb.Reset();
    storemanager_->DeletePacket(tmidPacket->PacketName(user_params),
      signed_request, boost::any_cast<std::string>(pub_keys["ANTMID"]),
      signed_public_key, SYSTEM_PACKET,
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
  }

  ss_->SetPin(new_pin);
  ss_->SetSmidRid(ss_->MidRid());
  ss_->SetMidRid(boost::any_cast<uint32_t>(mid_result["rid"]));
  delete midPacket;
  delete smidPacket;
  delete tmidPacket;

  return OK;
}

Exitcode Authentication::ChangePassword(std::string ser_da,
                                        ph::PacketParams priv_keys,
                                        ph::PacketParams pub_keys,
                                        std::string new_password) {
  //   if (!CheckPassword(new_password) || new_password == ss_->Password())
  //     return INVALID_PASSWORD;
  std::string old_password = ss_->Password();
  ss_->SetPassword(new_password);
  if (SaveSession(ser_da, priv_keys, pub_keys) == OK) {
    return OK;
  } else {
    ss_->SetPassword(old_password);
    return FAIL;
  }
}

std::string Authentication::createSignaturePackets(
    const ph::SystemPackets &type, const PacketType &type_da,
    std::string &public_key) {
  ph::PacketParams params;
  ph::SignaturePacket *sigPacket =
      static_cast<ph::SignaturePacket*>(ph::PacketFactory::Factory(type));
  params = sigPacket->Create(params);

  AuthCallbackResult cb;
  bool result = false;
  while (!result) {
    cb.Reset();
    storemanager_->IsKeyUnique(boost::any_cast<std::string>(params["name"]),
      boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
    GenericResponse is_unique_res;
    is_unique_res.ParseFromString(cb.result);
    if (is_unique_res.result() == kAck)
      result = true;
    else
      params = sigPacket->Create(params);
  }
  std::string signed_public_key(""), signed_request("");
  CreateSignedRequest(boost::any_cast<std::string>(params["privateKey"]),
                      boost::any_cast<std::string>(params["publicKey"]),
                      boost::any_cast<std::string>(params["name"]),
                      &signed_public_key,
                      &signed_request);
  cb.Reset();
  storemanager_->StorePacket(boost::any_cast<std::string>(params["name"]),
    boost::any_cast<std::string>(params["ser_packet"]), signed_request,
    boost::any_cast<std::string>(params["publicKey"]),
    signed_public_key, SYSTEM_PACKET, false,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  ss_->AddKey(type_da, boost::any_cast<std::string>(params["name"]),
              boost::any_cast<std::string>(params["privateKey"]),
              boost::any_cast<std::string>(params["publicKey"]));

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
    const std::string &public_key, const std::string &hex_packet_name,
    std::string *signed_public_key, std::string *signed_request) {
  std::string non_hex_key("");
  base::decode_from_hex(hex_packet_name, &non_hex_key);
  crypto::Crypto cry_obj_;
  cry_obj_.set_symm_algorithm(crypto::AES_256);
  cry_obj_.set_hash_algorithm(crypto::SHA_512);
  *signed_public_key = cry_obj_.AsymSign(public_key,
                                         "",
                                         private_key,
                                         crypto::STRING_STRING);
  *signed_request = cry_obj_.AsymSign(
      cry_obj_.Hash(public_key + *signed_public_key + non_hex_key,
                    "",
                    crypto::STRING_STRING,
                    true),
      "",
      private_key,
      crypto::STRING_STRING);
  return 0;
}

void Authentication::WaitForResult(const AuthCallbackResult &cb) {
  while (true) {
    {
      base::pd_scoped_lock gaurd(*mutex_);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
}

bool Authentication::GetMid(const std::string &username,
                            const std::string &pin,
                            int *rid) {
  ph::PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  ph::MidPacket *midPacket = static_cast<ph::MidPacket*>
    (ph::PacketFactory::Factory(ph::MID));
  std::string mid_name = midPacket->PacketName(params);
  AuthCallbackResult cb;
  std::string ser_packet = "";
  storemanager_->LoadPacket(mid_name,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GetResponse load_res;
  if ((!load_res.ParseFromString(cb.result)) ||
      (load_res.result() != kAck) ||
      (!load_res.has_content())) {
    delete midPacket;
    return false;
  }
  ser_packet = load_res.content();
  ph::PacketParams info = midPacket->GetData(ser_packet, username, pin);
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
  ph::PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  ph::SmidPacket *smidPacket = static_cast<ph::SmidPacket*>
    (ph::PacketFactory::Factory(ph::SMID));
  std::string smid_name = smidPacket->PacketName(params);
  AuthCallbackResult cb;
  std::string ser_packet = "";
  storemanager_->LoadPacket(smid_name,
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GetResponse load_res;
  if ((!load_res.ParseFromString(cb.result)) ||
      (load_res.result() != kAck) ||
      (!load_res.has_content())) {
    delete smidPacket;
    return false;
  }
  ser_packet = load_res.content();
  ph::PacketParams info = smidPacket->GetData(ser_packet, username, pin);
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

void Authentication::GetUserTmid(base::callback_func_type cb, bool smid) {
  ph::TmidPacket *tmidPacket = static_cast<ph::TmidPacket*>(
                               ph::PacketFactory::Factory(ph::TMID));
  ph::PacketParams params;
  params["username"] = ss_->Username();
  params["PIN"] = ss_->Pin();
  params["rid"] = ss_->MidRid();
  std::string tmid_name = tmidPacket->PacketName(params);
  storemanager_->LoadPacket(tmid_name,
      boost::bind(&Authentication::GetUserTmidCallback, this, _1, smid, cb));
}

void Authentication::GetUserTmidCallback(const std::string& result,
                                         bool smid,
                                         base::callback_func_type cb) {
  GetResponse load_res;
  if ((!load_res.ParseFromString(result)) ||
      (load_res.result() != kAck) ||
      (!load_res.has_content())) {
#ifdef DEBUG
    if (!load_res.ParseFromString(result))
      printf("Doesn't parse as GetUserTmidCallback.\n");
    if (load_res.result() != kAck)
      printf("GetUserTmidCallback came back with failure.\n");
    if (!load_res.has_content())
      printf("GetUserTmidCallback came back with no content.\n");
#endif
    if (smid) {
      load_res.Clear();
      load_res.set_result(kNack);
      std::string ser_res;
      load_res.SerializeToString(&ser_res);
      cb(ser_res);
      return;
    }
    if (ss_->SmidRid() == 0) {
      int rid;
      if (!GetSmid(ss_->Username(), ss_->Pin(), &rid)) {
        load_res.Clear();
        load_res.set_result(kNack);
        std::string ser_res;
        load_res.SerializeToString(&ser_res);
        cb(ser_res);
        return;
      }
      ss_->SetSmidRid(rid);
      ss_->SetMidRid(rid);
      GetUserTmid(cb, true);
      return;
    } else {
      load_res.Clear();
      load_res.set_result(kNack);
      std::string ser_res;
      load_res.SerializeToString(&ser_res);
#ifdef DEBUG
      printf("Authentication::GetUserTmidCallback Failure\n");
#endif
      cb(ser_res);
      return;
    }
  }
  tmid_content = load_res.content();
#ifdef DEBUG
  printf("Authentication::GetUserTmidCallback returning content result\n");
#endif
  cb(result);
}

Exitcode Authentication::PublicUsernamePublicKey(
    const std::string &public_username,
    std::string &public_key) {
  ph::PacketParams params;
  params["publicname"] = public_username;
  ph::MpidPacket *mpidPacket =
    static_cast<ph::MpidPacket*>(ph::PacketFactory::Factory(ph::MPID));

  AuthCallbackResult cb;
  storemanager_->LoadPacket(mpidPacket->PacketName(params),
    boost::bind(&AuthCallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GetResponse load_res;
  if ((!load_res.ParseFromString(cb.result)) ||
      (load_res.result() != kAck) ||
      (!load_res.has_content())) {
    return NON_EXISTING_USER;
  }
  std::string ser_generic_packet = load_res.content();
  packethandler::GenericPacket gp;
  if (!gp.ParseFromString(ser_generic_packet)) {
    return FAIL;  //  Packet corrupt
  }

  public_key = gp.data();

  return OK;
}

void Authentication::CreateMSIDPacket(base::callback_func_type cb) {
  ph::PacketParams params;
  ph::SignaturePacket *sigPacket = static_cast<ph::SignaturePacket*>(
      ph::PacketFactory::Factory(ph::MSID));
  params = sigPacket->Create(params);
  storemanager_->IsKeyUnique(boost::any_cast<std::string>(params["name"]),
      boost::bind(&Authentication::CheckMSIDUnique_Callback, this, _1, 1,
                  params, cb));
}

void Authentication::CheckMSIDUnique_Callback(const std::string &result,
                                              int retry,
                                              ph::PacketParams params,
                                              base::callback_func_type cb) {
  // up to 10 retries to try to create a unique msid name
  if (retry > 10) {
    ph::CreateMSIDResult local_result;
    local_result.set_result(kNack);
    std::string ser_local_result;
    local_result.SerializeToString(&ser_local_result);
    cb(ser_local_result);
    return;
  }

  GenericResponse is_unique_res;
  if ((!is_unique_res.ParseFromString(result)) ||
      (is_unique_res.result() != kAck)) {
    // msid name already exists in kademlia.  creating a new msid
    ph::SignaturePacket *sigPacket = static_cast<ph::SignaturePacket*>\
      (ph::PacketFactory::Factory(ph::MSID));
    ph::PacketParams new_params;
    new_params = sigPacket->Create(new_params);
    storemanager_->IsKeyUnique(boost::any_cast<std::string>(new_params["name"]),
      boost::bind(&Authentication::CheckMSIDUnique_Callback, this, _1 ,
      retry+1, new_params, cb));
    return;
  } else {
    // key is unique
    std::string signed_public_key(""), signed_request("");
    CreateSignedRequest(boost::any_cast<std::string>(params["privateKey"]),
                        boost::any_cast<std::string>(params["publicKey"]),
                        boost::any_cast<std::string>(params["name"]),
                        &signed_public_key,
                        &signed_request);
    storemanager_->StorePacket(boost::any_cast<std::string>(params["name"]),
      boost::any_cast<std::string>(params["ser_packet"]), signed_request,
      boost::any_cast<std::string>(params["publicKey"]), signed_public_key,
      SYSTEM_PACKET, false, boost::bind(&Authentication::StoreMSID_Callback,
      this, _1, params, cb));
    return;
  }
}

void Authentication::StoreMSID_Callback(const std::string &result,
                                        ph::PacketParams params,
                                        base::callback_func_type cb) {
  StoreResponse result_msg;
  ph::CreateMSIDResult local_result;
  std::string str_local_result;
  if ((!result_msg.ParseFromString(result)) ||
      (result_msg.result() != kAck)) {
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
