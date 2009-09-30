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

VaultDaemon::~VaultDaemon() {
  if (registration_service_ != NULL) {
    local_ch_manager_->StopTransport();
    local_ch_manager_->ClearChannels();
    delete registration_service_;
    delete registration_channel_;
    delete local_ch_manager_;
  }

  std::string stop_ = "VaultDaemon stopping  ";
  boost::posix_time::ptime now_ = boost::posix_time::second_clock::local_time();
  stop_ += boost::posix_time::to_simple_string(now_);
  WriteToLog(stop_);
  if (pdvault_ != NULL) {
    pdvault_->Stop(true);
    pdvault_->CleanUp();
    delete pdvault_;
  }
}

void VaultDaemon::Status() {
  std::string out = base::itos(pdvault_->host_port()) + " - OK";
  WriteToLog(out);
}

void VaultDaemon::RegistrationNotification(const maidsafe::VaultConfig
      &vconfig) {
  {
    boost::mutex::scoped_lock gaurd(config_mutex_);
    std::fstream output(local_config_file_.string().c_str(),
        std::ios::out | std::ios::trunc | std::ios::binary);
    vconfig.SerializeToOstream(&output);
    output.close();
  }
}

void VaultDaemon::TakeOwnership() {
  while (!is_owned_) {
    if (ReadConfigInfo()) {
      StopNotOwnedVault();
      if (!StartOwnedVault()) {
        registration_service_->ReplyOwnVaultRequest(true);
        StartNotOwnedVault();
      } else {
        registration_service_->set_status(maidsafe::OWNED);
        registration_service_->ReplyOwnVaultRequest(false);
        is_owned_ = true;
      }
    } else {
      boost::this_thread::sleep(boost::posix_time::seconds(1.0));
    }
  }
  WriteToLog("Vault has been owned.\n");
  WriteToLog("Vault ID:         "+pdvault_->hex_node_id());
  WriteToLog("Vault IP & port:  "+pdvault_->host_ip()+":"+
      base::itos(pdvault_->host_port()));
}

int VaultDaemon::SetPaths() {
  // TODO(Fraser#5#): 2009-04-24 - This is repeated code - move to base?
  fs::path app_path("");
#if defined(MAIDSAFE_POSIX)
  app_path = fs::path("/var/cache/maidsafe/", fs::native);
#elif defined(MAIDSAFE_WIN32)
  TCHAR szpth[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL,
                                CSIDL_COMMON_APPDATA,
                                NULL,
                                0,
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
  try {
    if (!fs::exists(vault_path_))
      fs::create_directory(vault_path_);
  }
  catch(const std::exception &ex_) {
    WriteToLog("Can't create maidsafe vault dir.");
    WriteToLog(ex_.what());
    return -1;
  }
  config_file_ = vault_path_;
  config_file_ /= ".config";
  kad_config_file_ = vault_path_;
  kad_config_file_ /= ".kadconfig";
  local_config_file_ = fs::path(".config", fs::native);
  return 0;
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
  base::callback_func_type cb;
//  pdvault_->ValidityCheck(cb);
}

bool VaultDaemon::StartVault() {
  std::string init = "VaultDaemon starting  ";
  boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
  init += boost::posix_time::to_simple_string(now);
  WriteToLog(init);
  if (0 != SetPaths()) {
    WriteToLog("Failed to set path to config file - can't start vault.\n");
    return false;
  }
  bool started_registration_service = true;
  // No Config file, starting a not owned vault
  local_ch_manager_ = new rpcprotocol::ChannelManager();
  registration_channel_ = new rpcprotocol::Channel(local_ch_manager_);
  registration_service_ = new maidsafe_vault::RegistrationService(boost::bind(
      &VaultDaemon::RegistrationNotification, this, _1));
  registration_channel_->SetService(registration_service_);
  local_ch_manager_->RegisterChannel(
      registration_service_->GetDescriptor()->name(), registration_channel_);
  if (0 != local_ch_manager_->StartLocalTransport(kLocalPort)) {
    local_ch_manager_->ClearChannels();
    delete registration_service_;
    delete registration_channel_;
    delete local_ch_manager_;
    registration_service_ = NULL;
    registration_channel_ = NULL;
    local_ch_manager_ = NULL;
    started_registration_service = false;
  }
  if (!ReadConfigInfo()) {
    if (!started_registration_service) {
      WriteToLog("Failed to start registration service");
      return false;
    }
    if (!StartNotOwnedVault())
      return false;
    else
      TakeOwnership();
  } else {
    if (!StartOwnedVault()) {
      return false;
    } else {
      if (registration_service_ != NULL)
        registration_service_->set_status(maidsafe::OWNED);
      is_owned_ = true;
    }
  }
  return true;
}

bool VaultDaemon::ReadConfigInfo() {
  fs::path file;
  try {
    std::string out;
    boost::mutex::scoped_lock gaurd(config_mutex_);
    if (fs::exists(local_config_file_)) {
      file = local_config_file_;
      out = "Using local config file: ./" + local_config_file_.string();
    } else if (fs::exists(config_file_)) {
      file = config_file_;
      out = "Using config file at " + config_file_.string();
    } else {
      out = "Can't find config file at ";
      out += config_file_.string() + " or ./" + local_config_file_.string();
    }
    WriteToLog(out);
  }
  catch(const std::exception &e) {
    std::string err = "Can't access locations for config file at ";
    err += config_file_.string() + " or " + local_config_file_.string();
    WriteToLog(err);
    WriteToLog(e.what());
  }
  if (file != "") {
    std::ifstream input(file.string().c_str(), std::ios::in | std::ios::binary);
    maidsafe::VaultConfig vault_config;
    if (!vault_config.ParseFromIstream(&input)) {
      WriteToLog("Failed to parse configuration file.\n");
      return false;
    }

    pmid_public_ = vault_config.pmid_public();
    pmid_private_ = vault_config.pmid_private();
    signed_pmid_public_ = vault_config.signed_pmid_public();
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
  } else {
    return false;
  }
  return true;
}

bool VaultDaemon::StartNotOwnedVault() {
  crypto::Crypto co;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  std::string signed_pubkey = co.AsymSign(keys.public_key(), "",
      keys.private_key(), crypto::STRING_STRING);
  fs::path chunkstore_dir(vault_path_);
  chunkstore_dir /= "Chunkstore";
  boost::uint64_t space = 1024*1024*1024;  // 1GB
  pdvault_ = new PDVault(keys.public_key(), keys.private_key(), signed_pubkey,
      chunkstore_dir.string(), 0, false, false, kad_config_file_.string(),
      space, 0);
  pdvault_->Start(false);
  if (pdvault_->vault_status() == kVaultStopped) {
    WriteToLog("Failed to start a not owned vault");
    return false;
  }
  WriteToLog("Vault waiting to be owned started.\n");
  WriteToLog("Vault ID:         "+pdvault_->hex_node_id());
  WriteToLog("Vault IP & port:  "+pdvault_->host_ip()+":"+
      base::itos(pdvault_->host_port()));
  return true;
}

void VaultDaemon::StopNotOwnedVault() {
  pdvault_->Stop(true);
  delete pdvault_;
  pdvault_ = NULL;
  fs::path chunkstore_dir(vault_path_);
  chunkstore_dir /= "Chunkstore";
  fs::remove_all(chunkstore_dir);
}

bool VaultDaemon::StartOwnedVault() {
  if (pdvault_ != NULL)
    return false;
  pdvault_ = new PDVault(pmid_public_, pmid_private_, signed_pmid_public_,
      chunkstore_dir_, port_, false, false, kad_config_file_.string(),
      vault_available_space_, used_space_);
  pdvault_->Start(false);
  if (pdvault_->vault_status() == kVaultStopped) {
    WriteToLog("Failed To Start Owned Vault with info in config file");
    return false;
  }
  registration_service_->set_status(maidsafe::OWNED);
  return true;
}
}  // namespace maidsafe_vault
