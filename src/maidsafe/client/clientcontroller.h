/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-11.09.12
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_CLIENTCONTROLLER_H_
#define MAIDSAFE_CLIENT_CLIENTCONTROLLER_H_

#include <gtest/gtest_prod.h>
#include <maidsafe/base/utils.h>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "fs/filesystem.h"
#include "maidsafe/client/authentication.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/sehandler.h"

namespace maidsafe {

namespace test {
class ClientControllerTest;
class ClientControllerTest_BEH_MAID_CC_HandleMessages_Test;
class ClientControllerTest_FUNC_MAID_NET_CC_HandleMessages_Test;
class ClientControllerTest_FUNC_MAID_CC_ClearStaleMessages_Test;
class ClientControllerTest_FUNC_MAID_NET_CC_ClearStaleMessages_Test;
}

class ChunkStore;

class CCCallback {
 public:
  CCCallback() : result_(), return_code_(kPendingResult), mutex_(), cv_() {}
  void StringCallback(const std::string &result);
  void ReturnCodeCallback(const ReturnCode &return_code);
  std::string WaitForStringResult();
  ReturnCode WaitForReturnCodeResult();
 private:
  std::string result_;
  ReturnCode return_code_;
  boost::mutex mutex_;
  boost::condition_variable cv_;
};

class BPCallback {
 public:
  BPCallback() : result(kGeneralError), end_point(), status(0) {}
  void ContactInfoCallback(const ReturnCode &res,
                           const std::list<EndPoint> &ep,
                           const PersonalDetails &pd,
                           const boost::uint32_t &st) {
    result = res;
    end_point = ep;
    personal_details = pd;
    status = st;
  }

  void Reset() {
    end_point.clear();
    personal_details.Clear();
    result = kGeneralError;
  }

  ReturnCode result;
  std::list<EndPoint> end_point;
  PersonalDetails personal_details;
  boost::uint32_t status;
};

struct VaultConfigParameters {
  VaultConfigParameters() : vault_type(0), space(0), port(0), directory() {}
  int vault_type;
  boost::uint32_t space;
  boost::uint32_t port;
  std::string directory;
};

class ClientController {
 public:
  static ClientController *getInstance();
  static void Destroy();
  int Init(boost::uint8_t k);
  // Close connection to kademlia/stub storage.  Currently with UDT, if
  // clean_up_transport is true, UDT cannot be restarted, so this is a
  // permanent cessation of the transport layer.
  void CloseConnection(bool clean_up_transport);
  void StopRvPing();
  int ParseDa();
  int SerialiseDa();
  int CheckUserExists(const std::string &username,
                      const std::string &pin,
                      DefConLevels level);
  bool CreateUser(const std::string &username,
                  const std::string &pin,
                  const std::string &password,
                  const VaultConfigParameters &vcp);
  bool ValidateUser(const std::string &password);
  bool Logout();
  int SaveSession();
  bool LeaveMaidsafeNetwork();
  bool CreatePublicUsername(const std::string &public_username);
  bool ChangeUsername(const std::string &new_username);
  bool ChangePin(const std::string &new_pin);
  bool ChangePassword(const std::string &new_password);
  int ChangeConnectionStatus(int status);
  int RunDbEncQueue();
  inline bool initialised() { return initialised_; }

  // Messages
  typedef boost::function<void(const InstantMessage&)> IMNotifier;
  bool GetMessages();
  int HandleMessages(
      std::list<ValidatedBufferPacketMessage> *valid_messages);
  int HandleReceivedShare(const PrivateShareNotification &psn,
                          const std::string &name);
  int HandleDeleteContactNotification(const std::string &sender);
  int HandleInstantMessage(
      const ValidatedBufferPacketMessage &vbpm);
  int HandleAddContactRequest(const ContactInfo &ci, const std::string &sender);
  int HandleAddContactResponse(const ContactInfo &ci,
                               const std::string &sender);
  int GetInstantMessages(std::list<InstantMessage> *messages);
  int SendInstantMessage(const std::string &message,
                         const std::vector<std::string> &contact_names,
                         const std::string &conversation);
  int SendInstantFile(std::string *filename,
                      const std::string &msg,
                      const std::vector<std::string> &contact_names,
                      const std::string &conversation);
  int SendEmail(const std::string &subject, const std::string &msg,
                const std::vector<std::string> &to,
                const std::vector<std::string> &cc,
                const std::vector<std::string> &bcc,
                const std::string &conversation);
  int AddInstantFile(const InstantFileNotification &ifm,
                     const std::string &location);
  void onInstantMessage(const std::string &message,
                        const boost::uint32_t&,
                        const boost::int16_t&,
                        const double&);
  void SetIMNotifier(IMNotifier imn);

  // Contact operations
  int ContactList(const std::string &pub_name,
                  const SortingMode &sm,
                  std::vector<maidsafe::Contact> *c_list);
  int AddContact(const std::string &public_name);
  int DeleteContact(const std::string &public_name);

  // Share operations
  int GetShareList(const SortingMode &sm,
                   const ShareFilter &sf,
                   const std::string &pub_name,
                   std::list<maidsafe::PrivateShare> *ps_list);
  int ShareList(const SortingMode &sm, const ShareFilter &sf,
                std::list<std::string> *share_list);
  int GetSortedShareList(const SortingMode &sm,
                         const std::string &pub_name,
                         std::list<maidsafe::private_share> *ps_list);
  int CreateNewShare(const std::string &name,
                     const std::set<std::string> &admins,
                     const std::set<std::string> &readonlys);

  // Vault operations
  bool PollVaultInfo(std::string *chunkstore,
                     boost::uint64_t *offered_space,
                     boost::uint64_t *free_space,
                     std::string *ip,
                     boost::uint32_t *port);
  bool VaultContactInfo();
  OwnLocalVaultResult SetLocalVaultOwned(
      const boost::uint32_t &port,
      const boost::uint64_t &space,
      const std::string &vault_dir) const;
  bool IsLocalVaultOwned();


  // FUSE based stuff here
  bool ReadOnly(const std::string &path, bool gui);
  char DriveLetter();
  int mkdir(const std::string &path);
  int rename(const std::string &path, const std::string &path2);
  int rmdir(const std::string &path);
  int getattr(const std::string &path, std::string *ser_mdm);
  int readdir(const std::string &path,  // NOLINT - readdir_r suggested
              std::map<std::string, ItemType> *children);
  int mknod(const std::string &path);
  int unlink(const std::string &path);
  int link(const std::string &path, const std::string &path2);
  int cpdir(const std::string &path, const std::string &path2);
  int utime(const std::string &path);
  int atime(const std::string &path);
  // int statfs();
  int open(const std::string &path);
  int read(const std::string &path);
  int write(const std::string &path);
  int create(const std::string &path);

  // static int symlink(const char *, const char *);
  // static int readlink(const char *, char *, size_t);
  static int chmod(const std::string &path, int perm);
  static int chown(const std::string &path, std::string &user);
  static int truncate();
  static int flush();
  static int release();
  static int fsync();
  static int setxattr();
  static int getxattr();
  static int listxattr();
  static int removexattr();
  static int opendir(const std::string &path);
  static int getdir(const std::string &path);
  static int releasedir(const std::string &path);
  static int fsyncdir();
  static void *init();
  // static void destroy(void *);
  static int access();
  static int ftruncate();
  static int fgetattr(const std::string &path);

  void RegisterImNotifiers(boost::function<void(const std::string&)> msg_not,
      boost::function<void(const std::string&, const int&)> conn_not);

  bs2::connection ConnectToOnFileNetworkStatus(
      const OnFileNetworkStatus::slot_type &slot);

 private:
  friend class test::ClientControllerTest;
  friend class test::ClientControllerTest_BEH_MAID_CC_HandleMessages_Test;
  friend class test::ClientControllerTest_FUNC_MAID_NET_CC_HandleMessages_Test;
  friend class test::ClientControllerTest_FUNC_MAID_CC_ClearStaleMessages_Test;
  friend class
      test::ClientControllerTest_FUNC_MAID_NET_CC_ClearStaleMessages_Test;

  // Functions
  ClientController();
  ~ClientController() { }
  ClientController &operator=(const ClientController&);
  ClientController(const ClientController&);
  bool JoinKademlia();
  int BackupElement(const std::string &path, const DirType dir_type,
                    const std::string &msid);
  int RetrieveElement(const std::string &path);
  int RemoveElement(const std::string &element_path);
  // If the database of the parent doesn't exist, it is decrypted.  GetDb also
  // sets db type and msid if it exists for parent dir or sets it to "" if not.
  int GetDb(const std::string &path_, DirType *dir_type, std::string *msid);
  // Add db to encryption queue (to be saved during session save) if bool ==
  // false or saves db immediately otherwise.
  int SaveDb(const std::string &db_path,
             const DirType dir_type,
             const std::string &msid,
             const bool &immediate_save);
  int RemoveDb(const std::string &path_);
  DirType GetDirType(const std::string &path_);
  int PathDistinction(const std::string &path, std::string *msid);
  void ClearStaleMessages();
  void SetLocalVaultOwnedCallback(const OwnLocalVaultResult &result,
                                  const std::string &pmid_name,
                                  bool *callback_arrived,
                                  OwnLocalVaultResult *res);
  VaultStatus LocalVaultOwned() const;
  void LocalVaultOwnedCallback(const VaultStatus &result,
                               bool *callback_arrived,
                               VaultStatus *res);
  std::string GenerateBPInfo();
  std::vector<std::string> GetOffLineContacts();
  void FileUpdate(const std::string &file, int percentage);
  bool AddToPendingFiles(const std::string &file);
  bool RemoveFromPendingFiles(const std::string &file);

  // Variables
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  boost::shared_ptr<StoreManagerInterface> sm_;
  Authentication auth_;
  SessionSingleton *ss_;
  std::string ser_da_, ser_dm_;
  std::map<std::string, std::pair<std::string, std::string> > db_enc_queue_;
  SEHandler seh_;
  static ClientController *single;
  std::list<InstantMessage> instant_messages_;
  std::map<std::string, boost::uint32_t> received_messages_;
  boost::mutex rec_msg_mutex_;
  boost::thread clear_messages_thread_;
  std::string client_store_;
  bool initialised_;
  bool logging_out_;
  bool logged_in_;
  IMNotifier imn_;
  boost::uint8_t K_;
  boost::uint16_t upper_threshold_;
  bs2::connection to_seh_file_update_;
  std::multimap<std::string, int> pending_files_;
  boost::mutex pending_files_mutex_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTCONTROLLER_H_
