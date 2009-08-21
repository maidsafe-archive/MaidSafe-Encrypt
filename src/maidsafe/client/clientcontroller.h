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

#include <maidsafe/utils.h>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "boost/threadpool.hpp"  // NB - This is NOT an accepted boost lib.
#include "fs/filesystem.h"
#include "maidsafe/client/authentication.h"
#include "maidsafe/client/clientbufferpackethandler.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/messagehandler.h"
#include "maidsafe/client/sehandler.h"

namespace maidsafe {

class ChunkStore;

class CC_CallbackResult {
 public:
  CC_CallbackResult();
  void CallbackFunc(const std::string &res);
  void Reset();
  std::string result;
};

class ClientController {
 public:
  static ClientController *getInstance();
  static void Destroy();

  bool Init();
  bool JoinKademlia();
  // Close connection to kademlia/stub storage.  Currently with UDT, if
  // clean_up_transport is true, UDT cannot be restarted, so this is a
  // permanent cessation of the transport layer.
  void CloseConnection(bool clean_up_transport);

  int ParseDa();
  int SerialiseDa();
  Exitcode CheckUserExists(const std::string &username,
                           const std::string &pin,
                           base::callback_func_type cb,
                           DefConLevels level);
  bool CreateUser(const std::string &username,
                  const std::string &pin,
                  const std::string &password);
  int SetVaultConfig(const std::string &pmid_public,
                     const std::string &pmid_private);
  bool ValidateUser(const std::string &password);

  bool Logout();
  bool LeaveMaidsafeNetwork();
  bool CreatePublicUsername(std::string public_username);
  bool ChangeUsername(std::string new_username);
  bool ChangePin(std::string new_pin);
  bool ChangePassword(std::string new_password);
  bool AuthoriseUsers(std::set<std::string> users);
  bool DeauthoriseUsers(std::set<std::string> users);
  int ChangeConnectionStatus(int status);
  int RunDbEncQueue();

  // Messages
  bool GetMessages();
  int HandleMessages(std::list<std::string> *msgs);
  int HandleReceivedShare(const packethandler::PrivateShareNotification &psn,
                          const std::string &name);
  int HandleDeleteContactNotification(const std::string &sender);
  int HandleInstantMessage(
    packethandler::ValidatedBufferPacketMessage &vbpm);
  int HandleAddContactRequest(const packethandler::ContactInfo &ci,
    const std::string &sender);
  int HandleAddContactResponse(const packethandler::ContactInfo &ci,
    const std::string &sender);
  int GetInstantMessages(std::list<packethandler::InstantMessage> *messages);
  int SendInstantMessage(const std::string &message,
                         const std::vector<std::string> &contact_names,
                         bool test = false);
  int SendInstantFile(std::string *filename, const std::string &msg,
                      const std::vector<std::string> &contact_names);
  int AddInstantFile(const packethandler::InstantFileNotification &ifm,
                     const std::string &location);

  // Contact operations
  int ContactList(std::vector<maidsafe::Contact> *c_list,
                  const std::string &pub_name);
  int AddContact(const std::string &public_name);
  int DeleteContact(const std::string &public_name);

  // Share operations
  int GetShareList(std::list<maidsafe::PrivateShare> *ps_list,
                   const std::string &pub_name);
  int CreateNewShare(const std::string &name,
                     const std::set<std::string> &admins,
                     const std::set<std::string> &readonlys);

  // Register Vault operations
  void OwnLocalVault(const boost::uint32_t &port, const boost::uint64_t &space,
      const std::string &chunkstore_dir);

  // FUSE based stuff here
  bool ReadOnly(const std::string &path, bool gui);
  char DriveLetter();
  int mkdir(const std::string &path);
  int rename(const std::string &path, const std::string &path2);
  int rmdir(const std::string &path);
  int getattr(const std::string &path, std::string &ser_mdm);
  int readdir(const std::string &path,  // NOLINT - readdir_r suggested
              std::map<std::string, itemtype> &children);
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

 private:
  // Functions
  ClientController();
  ~ClientController() { }
  ClientController &operator=(const ClientController&);
  ClientController(const ClientController&);
  void WaitForResult(const CC_CallbackResult &cb);
  int BackupElement(const std::string &path,
                    const DirType dir_type,
                    const std::string &msid);
  int RetrieveElement(const std::string &path);
  int RemoveElement(std::string path);
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
  bool ClearStaleMessages();
  void OwnLocalVault_Callback(const OwnVaultResult &result, const
      std::string &pmid_name);

  // Variables
  Authentication *auth_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  StoreManagerInterface *sm_;
  SessionSingleton *ss_;
  MessageHandler *msgh_;
  packethandler::ClientBufferPacketHandler *cbph_;
  std::string ser_da_;
  std::map<std::string, std::pair<std::string, std::string> >db_enc_queue_;
  SEHandler *seh_;
  static ClientController *single;
  boost::recursive_mutex mutex_;
  std::list<packethandler::InstantMessage> messages_;
  file_system::FileSystem fsys_;
  std::map<std::string, boost::uint32_t> received_messages_;
  boost::mutex rec_msg_mutex_;
  boost::threadpool::thread_pool<
      boost::threadpool::task_func,
      boost::threadpool::fifo_scheduler,
      boost::threadpool::static_size,
      boost::threadpool::resize_controller,
      boost::threadpool::immediately> thread_pool_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTCONTROLLER_H_
