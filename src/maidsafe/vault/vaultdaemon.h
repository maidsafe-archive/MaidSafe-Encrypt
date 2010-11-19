/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Daemon for running a PD vault.
* Version:      1.0
* Created:      2009-02-21-23.55.54
* Revision:     none
* Author:       Team
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

#ifndef MAIDSAFE_VAULT_VAULTDAEMON_H_
#define MAIDSAFE_VAULT_VAULTDAEMON_H_

#include <boost/filesystem.hpp>
#include <maidsafe/transport/transportudt.h>
#include <maidsafe/transport/transporthandler-api.h>
#include <maidsafe/rpcprotocol/channel-api.h>
#include <maidsafe/rpcprotocol/channelmanager-api.h>
#include <string>

namespace fs = boost::filesystem;

int WriteToLog(std::string str);

namespace maidsafe {

class VaultConfig;

namespace vault {

namespace test { class VaultDaemonRegistrationTest; }

class PDVault;
class RegistrationService;

const boost::uint16_t kRsaKeySize = 4096;

class VaultDaemon {
  // A daemon class to assist PD vault functions
 public:
  VaultDaemon(const int &port, const std::string &vault_dir,
              const boost::uint8_t k);
  ~VaultDaemon();
  void Status();
  // Returns false if it fails to start the already owned vault or the not owned
  // vault.
  bool StartVault();
  fs::path vault_path() const { return vault_path_; }
  friend class test::VaultDaemonRegistrationTest;
 private:
  void StopRegistrationService();
  // Start vaultdaemon without an owner.  Once config file is located and read
  // owner of PMID in config file now owns the vault.
  bool TakeOwnership();
  // set paths to local or communal config file
  int SetPaths();
  // Update/Delete vault every time a vault node starts.
  void SyncVault();
  // Republish all the chunk references.
  void RepublishChunkRef();
  // Do validity check on all chunks held in vault
  void ValidityCheck();
  void RegistrationNotification(const VaultConfig &vconfig);
  bool StartNotOwnedVault();
  bool StartOwnedVault();
  int StopNotOwnedVault();
  int ReadConfigInfo();

  boost::shared_ptr<PDVault> pdvault_;
  bool is_owned_;
  fs::path config_file_, kad_config_file_, app_path_, not_owned_path_;
  fs::path vault_path_;
  std::string pmid_public_, pmid_private_, signed_pmid_public_;
  boost::uint16_t port_;
  boost::uint64_t vault_available_space_, used_space_;
  transport::TransportUDT local_udt_transport_, global_udt_transport_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<rpcprotocol::Channel> registration_channel_;
  boost::shared_ptr<RegistrationService> registration_service_;
  boost::mutex config_mutex_;
  boost::uint8_t K_;
  std::string test_config_postfix_;
  VaultDaemon(const VaultDaemon&);
  VaultDaemon& operator=(const VaultDaemon&);
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_VAULTDAEMON_H_
