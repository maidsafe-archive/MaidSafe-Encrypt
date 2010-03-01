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
 *  Created on: Dec 16, 2008
 *      Author: Haiyang
 */

#include "maidsafe/vault/vaultdaemon.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem/fstream.hpp>
#include <google/protobuf/descriptor.h>
#ifdef MAIDSAFE_WIN32
#include <shlwapi.h>
#endif
#include <iostream>  // NOLINT Fraser - required for handling .config file

#include "fs/filesystem.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

//  #if defined(MAIDSAFE_APPLE)
//    int WriteToLog(std::string str) { return 0; }
//  #endif

namespace maidsafe_vault {

VaultDaemon::VaultDaemon(const int &port, const std::string &vault_dir)
    : pdvault_(),
      val_check_(),
      is_owned_(false),
      config_file_(),
      kad_config_file_(),
      vault_path_(vault_dir, fs::native),
      pmid_public_(),
      pmid_private_(),
      signed_pmid_public_(),
      chunkstore_dir_(),
      port_(port),
      vault_available_space_(0),
      used_space_(0),
      local_udt_transport_(),
      global_udt_transport_(),
      transport_handler_(),
      channel_manager_(&transport_handler_),
      registration_channel_(),
      registration_service_(),
      config_mutex_() {
  boost::int16_t trans_id;
  transport_handler_.Register(&local_udt_transport_, &trans_id);
  transport_handler_.Register(&global_udt_transport_, &trans_id);
}

VaultDaemon::~VaultDaemon() {
  std::string stop("VaultDaemon stopping ");
  StopRegistrationService();
  boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
  stop += boost::posix_time::to_simple_string(now);
  WriteToLog(stop);
  if (pdvault_.get() != NULL) {
    pdvault_->Stop();
    pdvault_->CleanUp();
  }
}

void VaultDaemon::StopRegistrationService() {
//  if (registration_service_.get() != NULL) {
//    local_udt_transport_.Stop();
//    channel_manager_.ClearChannels();
//  }
  WriteToLog("Stopped registration service\n");
}

void VaultDaemon::Status() {
  WriteToLog("OK");
}

void VaultDaemon::RegistrationNotification(
    const maidsafe::VaultConfig &vconfig) {
  boost::mutex::scoped_lock gaurd(config_mutex_);
  std::fstream output(config_file_.string().c_str(),
      std::ios::out | std::ios::trunc | std::ios::binary);
  vconfig.SerializeToOstream(&output);
  output.close();
}

bool VaultDaemon::TakeOwnership() {
  while (!is_owned_) {
    int return_code = ReadConfigInfo();
    if (return_code == kSuccess) {
      if (StopNotOwnedVault() != kSuccess) {
        WriteToLog("Unowned vault won't stop.\n");
        StopRegistrationService();
        return false;
      }
      pdvault_.reset();
      if (!StartOwnedVault()) {
        registration_service_->ReplySetLocalVaultOwnedRequest(true);
        StartNotOwnedVault();
      } else {
        registration_service_->set_status(maidsafe::OWNED);
        registration_service_->ReplySetLocalVaultOwnedRequest(false);
        is_owned_ = true;
      }
    } else if (return_code == kVaultDaemonWaitingPwnage) {
      boost::this_thread::sleep(boost::posix_time::seconds(1.0));
    } else {
                                                printf("return_code = %i\n", return_code);
      StopRegistrationService();
      return false;
    }
  }
  WriteToLog("Vault has been owned.\n");
  WriteToLog("Vault ID:         " + base::EncodeToHex(pdvault_->node_id()));
  WriteToLog("Vault IP & port:  " + pdvault_->host_ip()+":"+
      base::itos(pdvault_->host_port()));
  StopRegistrationService();
  return true;
}

int VaultDaemon::SetPaths() {
  // TODO(Fraser#5#): 2009-04-24 - This is repeated code - move to base?
  if (vault_path_ == fs::path("")) {
    fs::path app_path("");
#if defined(MAIDSAFE_POSIX)
    app_path = fs::path("/var/cache/maidsafe/", fs::native);
#elif defined(MAIDSAFE_WIN32)
    TCHAR szpth[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0,
        szpth))) {
      std::ostringstream stm;
      const std::ctype<char> &ctfacet =
          std::use_facet< std::ctype<char> >(stm.getloc());
      for (size_t i = 0; i < wcslen(szpth); ++i)
        stm << ctfacet.narrow(szpth[i], 0);
      app_path = fs::path(stm.str(), fs::native);
      app_path /= "maidsafe";
    }
#elif defined(MAIDSAFE_APPLE)
    app_path = fs::path("/Library/maidsafe/", fs::native);
#endif
    vault_path_ = app_path;
    vault_path_ /= "vault";
  }
  try {
    if (!fs::exists(vault_path_))
      fs::create_directory(vault_path_);
  }
  catch(const std::exception &ex_) {
    WriteToLog("Can't create maidsafe vault dir.");
    WriteToLog(ex_.what());
    return kVaultDaemonException;
  }
  config_file_ = vault_path_;
  config_file_ /= ".config";
  kad_config_file_ = vault_path_;
  kad_config_file_ /= ".kadconfig";
  return kSuccess;
}

void VaultDaemon::SyncVault() {
  base::callback_func_type cb;
  pdvault_->SyncVault(cb);
}

void VaultDaemon::RepublishChunkRef() {
  base::callback_func_type cb;
  pdvault_->RepublishChunkRef(cb);
}

void VaultDaemon::ValidityCheck() {
//  base::callback_func_type cb;
//  pdvault_->ValidityCheck(cb);
}

bool VaultDaemon::StartVault() {
  std::string init("VaultDaemon starting ");
  boost::posix_time::ptime now =
      boost::posix_time::second_clock::local_time();
  init += boost::posix_time::to_simple_string(now);
  WriteToLog(init);
  if (kSuccess != SetPaths()) {
    WriteToLog("Failed to set path to config file - can't start vault.\n");
    return false;
  }
  bool started_registration_service = true;
  if (!channel_manager_.RegisterNotifiersToTransport()) {
    started_registration_service = false;
  } else {
    registration_channel_.reset(new rpcprotocol::Channel(&channel_manager_,
        &transport_handler_));
    registration_service_.reset(new maidsafe_vault::RegistrationService(
        boost::bind(&VaultDaemon::RegistrationNotification, this, _1)));
    registration_channel_->SetService(registration_service_.get());
    channel_manager_.RegisterChannel(
        registration_service_->GetDescriptor()->name(),
        registration_channel_.get());
    if (0 != transport_handler_.StartLocal(kLocalPort,
                                           local_udt_transport_.GetID())) {
      WriteToLog("Failed to start transport on port " + base::itos(kLocalPort));
      channel_manager_.ClearChannels();
      started_registration_service = false;
    }
  }
  if (ReadConfigInfo() != kSuccess) {
    if (!started_registration_service) {
      WriteToLog("Failed to start registration service");
      return false;
    }
    if (!StartNotOwnedVault())
      return false;
    else
      return TakeOwnership();
  } else {
    if (!StartOwnedVault()) {
      return false;
    } else {
      if (registration_service_.get() != NULL)
        registration_service_->set_status(maidsafe::OWNED);
      is_owned_ = true;
    }
  }
  StopRegistrationService();
  return true;
}

int VaultDaemon::ReadConfigInfo() {
  try {
    boost::mutex::scoped_lock gaurd(config_mutex_);
    if (!fs::exists(config_file_))
      return kVaultDaemonWaitingPwnage;
  }
  catch(const std::exception &e) {
    std::string err("Can't access location for config file at ");
    err += config_file_.string();
    WriteToLog(err);
    WriteToLog(e.what());
    return kVaultDaemonException;
  }
  std::ifstream input(config_file_.string().c_str(),
                      std::ios::in | std::ios::binary);
  maidsafe::VaultConfig vault_config;
  if (!vault_config.ParseFromIstream(&input)) {
    WriteToLog("Failed to parse configuration file.\n");
    return kVaultDaemonParseError;
  }

  pmid_public_ = vault_config.pmid_public();
  pmid_private_ = vault_config.pmid_private();
  signed_pmid_public_ = vault_config.signed_pmid_public();

  if (pmid_public_.empty() || pmid_private_.empty() ||
      signed_pmid_public_.empty()) {
#ifdef DEBUG
    if (pmid_public_.empty())
      WriteToLog("vault_config.pmid_public() empty.\n");
    if (pmid_private_.empty())
      WriteToLog("vault_config.pmid_private() empty.\n");
    if (signed_pmid_public_.empty())
      WriteToLog("vault_config.signed_pmid_public() empty.\n");
#endif
    return kVaultDaemonConfigError;
  }
  chunkstore_dir_ = vault_config.chunkstore_dir();
  vault_available_space_ = vault_config.available_space();
  if (vault_config.has_used_space())
    used_space_ = vault_config.used_space();
  else
    used_space_ = 0;
  // If a port between 5000 & 65535 inclusive is passed into VaultDaemon,
  // use that, otherwise try the config file.  As a last resort, set port to
  // 0 and PDVault will use a random port.
  if (vault_config.has_port() && vault_config.port() < kMinPort)
    port_ = vault_config.port();
  else
    port_ = 0;
  WriteToLog("Found config file at " + config_file_.string());
  WriteToLog("Chunkstore dir set to " + chunkstore_dir_);
  return kSuccess;
}

bool VaultDaemon::StartNotOwnedVault() {
  crypto::Crypto co;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  std::string signed_pubkey = co.AsymSign(keys.public_key(), "",
      keys.private_key(), crypto::STRING_STRING);
  fs::path chunkstore_dir(vault_path_);
  chunkstore_dir /= "Chunkstore";
  boost::uint64_t space(1024 * 1024 * 1024);  // 1GB
  pdvault_.reset(new PDVault(keys.public_key(), keys.private_key(),
      signed_pubkey, chunkstore_dir.string(), 0, false, false,
      kad_config_file_.string(), space, 0));
  pdvault_->Start(false);
  if (pdvault_->vault_status() == kVaultStopped) {
    WriteToLog("Failed to start a not owned vault");
    return false;
  }
  WriteToLog("Vault started.  Waiting to be owned.\n");
  WriteToLog("Vault ID:         " + base::EncodeToHex(pdvault_->node_id()));
  WriteToLog("Vault IP & port:  " + pdvault_->host_ip() + ":" +
             base::itos(pdvault_->host_port()));
  WriteToLog("Config file will be written to " + config_file_.string());
  return true;
}

int VaultDaemon::StopNotOwnedVault() {
  int result = pdvault_->Stop();
  if (result == kSuccess) {
    fs::path chunkstore_dir(vault_path_);
    chunkstore_dir /= "Chunkstore";
    fs::remove_all(chunkstore_dir);
  }
  return result;
}

bool VaultDaemon::StartOwnedVault() {
  if (pdvault_.get() != NULL)
    return false;
  pdvault_.reset(new PDVault(pmid_public_, pmid_private_, signed_pmid_public_,
      chunkstore_dir_, port_, false, false, kad_config_file_.string(),
      vault_available_space_, used_space_));
  pdvault_->Start(false);
  if (pdvault_->vault_status() == kVaultStopped) {
    WriteToLog("Failed To Start Owned Vault with info in config file");
    return false;
  }
  registration_service_->set_status(maidsafe::OWNED);
  return true;
}

}  // namespace maidsafe_vault
