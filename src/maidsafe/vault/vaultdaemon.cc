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
#ifdef MAIDSAFE_WIN32
#include <shlwapi.h>
#endif
#include <iostream>  // NOLINT Fraser - required for handling .config file

#include "fs/filesystem.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/general_messages.pb.h"

namespace fs = boost::filesystem;

//  #if defined(MAIDSAFE_APPLE)
//    int WriteToLog(std::string str) { return 0; }
//  #endif

namespace maidsafe_vault {

VaultDaemon::~VaultDaemon() {
  std::string stop_ = "VaultDaemon stopping  ";
  boost::posix_time::ptime now_ = boost::posix_time::second_clock::local_time();
  stop_ += boost::posix_time::to_simple_string(now_);
  WriteToLog(stop_);
  pdvault_->CleanUp();
}


void VaultDaemon::Status() {
  std::string out = base::itos(pdvault_->host_port()) + " - OK";
  WriteToLog(out);
}

void VaultDaemon::TakeOwnership() {
  std::string init_ = "VaultDaemon starting  ";
  boost::posix_time::ptime now_ = boost::posix_time::second_clock::local_time();
  init_ += boost::posix_time::to_simple_string(now_);
  WriteToLog(init_);
  if (0 != SetPaths()) {
    WriteToLog("Failed to set path to config file - can't start vault.\n");
    return;
  }
  fs::path file_("");
  while (!is_owned_) {
    try {
      std::string out("");
      if (fs::exists(local_config_file_)) {
        file_ = local_config_file_;
        out = "Using local config file: ./" + local_config_file_.string();
      } else if (fs::exists(config_file_)) {
        file_ = config_file_;
        out = "Using config file at " + config_file_.string();
      } else {
        out = "Can't find config file at ";
        out += config_file_.string() + " or ./" + local_config_file_.string();
      }
      WriteToLog(out);
    }
    catch(const std::exception ex_) {
      std::string err_ = "Can't access locations for config file at ";
      err_ += config_file_.string() + " or " + local_config_file_.string();
      WriteToLog(err_);
      WriteToLog(ex_.what());
    }
    if (file_ != "") {
      std::ifstream input_(file_.string().c_str(),
                           std::ios::in | std::ios::binary);
      base::VaultConfig vault_config_;
      if (!vault_config_.ParseFromIstream(&input_)) {
        WriteToLog("Failed to parse configuration file.\n");
        return;
      }
//      WriteToLog("Vault config details...");
//      WriteToLog(vault_config_.DebugString());
      pmid_public_ = vault_config_.pmid_public();
      pmid_private_ = vault_config_.pmid_private();
      signed_pmid_public_ = vault_config_.signed_pmid_public();
      chunkstore_dir_ = vault_config_.chunkstore_dir();
      vault_available_space_ = vault_config_.available_space();
      used_space_ = vault_config_.used_space();
      // If a port between 5000 & 65535 inclusive is passed into VaultDaemon,
      // use that, otherwise try the config file.  As a last resort, set port to
      // 0 and PDVault will use a random port.
      if (port_ < kMinPort) {
        if (vault_config_.has_port())
          port_ = vault_config_.port();
        else
          port_ = 0;
      }
      is_owned_ = true;
    } else {
      boost::this_thread::sleep(boost::posix_time::seconds(1.0));
    }
  }
  pdvault_ = boost::shared_ptr<PDVault>(new PDVault(pmid_public_,
                                                    pmid_private_,
                                                    signed_pmid_public_,
                                                    chunkstore_dir_,
                                                    port_,
                                                    kad_config_file_.string(),
                                                    vault_available_space_,
                                                    used_space_));
  bool port_forwarded = false;
  pdvault_->Start(port_forwarded);
  val_check_ = boost::shared_ptr<ValCheck>
      (new ValCheck(pdvault_, chunkstore_dir_));
  WriteToLog("Vault ID:         "+pdvault_->node_id());
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
  fs::path vault_path = app_path;
  vault_path /= "vault";
  try {
    if (!fs::exists(vault_path))
      fs::create_directory(vault_path);
  }
  catch(const std::exception &ex_) {
    WriteToLog("Can't create maidsafe vault dir.");
    WriteToLog(ex_.what());
    return -1;
  }
  config_file_ = vault_path;
  config_file_ /= ".config";


  kad_config_file_ = vault_path;
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
}  // namespace maidsafe_vault
