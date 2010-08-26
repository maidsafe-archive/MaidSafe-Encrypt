/*
 * copyright maidsafe.net limited 2009
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: May 9, 2009
 *      Author: Team
 */

#ifndef QT_CLIENT_CLIENT_CONTROLLER_H_
#define QT_CLIENT_CLIENT_CONTROLLER_H_

// qt
#include <QObject>
#include <QString>
#include <QDateTime>
#include <QDir>
#include <QStringList>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

// core
#include "maidsafe/client/clientinterface.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/utils.h"

// local
#include "qt/client/check_for_messages_thread.h"
#include "qt/client/contact.h"
#include "qt/client/profile.h"
#include "qt/client/presence.h"
#include "qt/client/share.h"

// Wrapper for maidsafe::ClientController
/*!
    Implements the ClientController notification interface and wraps up
    the ClientController methods in a Qt style API.

    The ClientController class, in conjunction with the other classes in
    qt/client, act as a layer between the Qt gui world and the maidsafe
    world.
*/

typedef boost::function<void(const std::string&,
                             const boost::uint32_t&,
                             const boost::int16_t&,
                             const double&)> IMNotifier;

#ifdef LOCAL_PDVAULT
  const boost::uint8_t kCheckForMessagesInterval = 3;
#else
  const boost::uint8_t kCheckForMessagesInterval = 60;
#endif

class ClientController : public QObject {
  Q_OBJECT
 public:

 struct PendingOps {
  QString name;
  int transBytes;
  int totalBytes;
};

  enum MessageType {
      TEXT,               // Instant message received from someone
      SHARE,              // Someone has shared something
      FILE,               // Someone has sent a file
      CONTACT_REQUEST,    // Someone has requested to add us
      CONTACT_RESPONSE,   // Someone has responed to our request
      CONTACT_DELETE,     // Someone has deleted us from their list
      INVITE,             // To invite someone to a conversation
      EMAIL               // Someone has sent an email
  };

  enum HintLevel {
      OFF,
      SMALL,
      FULL
  };

  enum DefConLevel {kDefCon1 = 1, kDefCon2, kDefCon3};

  enum ItemType {
  REGULAR_FILE = 0,
  SMALL_FILE = 1,
  EMPTY_FILE = 2,
  LOCKED_FILE = 3,
  DIRECTORY = 4,
  EMPTY_DIRECTORY = 5,
  LINK = 6,
  MAIDSAFE_CHUNK = 7,
  NOT_FOR_PROCESSING = 8,
  UNKNOWN = 9
};

  static ClientController* instance();
  void shutdown();
  bool Init();

  QString publicUsername() const;

  inline bool SetWinDrive(char win_drive) {
    return maidsafe::SessionSingleton::getInstance()->SetWinDrive(win_drive);
  }
  inline char WinDrive() {
    return maidsafe::SessionSingleton::getInstance()->WinDrive();
  }
  inline int Mounted() {
    return maidsafe::SessionSingleton::getInstance()->Mounted();
  }
  inline bool SetMounted(int mounted) {
    return maidsafe::SessionSingleton::getInstance()->SetMounted(mounted);
  }
  inline std::string SessionName() {
    return maidsafe::SessionSingleton::getInstance()->SessionName();
  }
  inline bool SetConnectionStatus(int status) {
    return maidsafe::SessionSingleton::getInstance()->
           SetConnectionStatus(status);
  }
  inline std::string TidyPath(std::string str) {
    return maidsafe::TidyPath(str);
  }

  char DriveLetter();
  bool Logout();

  /////////////////////////////
  // qt file browser methods //
  /////////////////////////////

  int getattr(const QString &path, QString &lastModified, QString &fileSize);
  int readdir(const QString &path,  // NOLINT
              std::map<std::string, ItemType> *children);
  int read(const QString &path);
  int write(const QString &path);
  int rename(const QString &path, const QString &path2);
  int mkdir(const QString &path);
  int rmdir(const QString &path);
  int mknod(const QString &path);

  bool CreatePublicUsername(const std::string &public_username);
  bool CreateUser(const QString &username,
                  const QString &pin,
                  const QString &password,
                  const int &vaultType,
                  const QString &space,
                  const QString &port,
                  const QString &directory);
  bool CheckUserExists(const std::string &username,
                  const std::string &pin,
                  DefConLevel level);
  int CreateNewShare(const std::string &name,
                     const std::set<std::string> &admins,
                     const std::set<std::string> &readonlys);
  bool ValidateUser(const std::string &password);

  int AddInstantFile(const QString &sender, const QString &filename,
                     const QString &tag,
                     int sizeLow, int sizeHigh,
                     const ClientController::ItemType &type,
                     const QString &s);

  bool getPendingOps(QList<PendingOps> &ops);

  ///////////////////////////////
  //// Conversation Handling ////
  ///////////////////////////////

  int ConversationList(std::list<std::string> *conversations);
  int AddConversation(const std::string &id);
  int RemoveConversation(const std::string &id);
  int ConversationExits(const std::string &id);
  void ClearConversations();

  // Settings
  bool ChangeUsername(const std::string &new_username);
  bool ChangePin(const std::string &new_pin);
  bool ChangePassword(const std::string &new_password);

  // Contacts
  ContactList contacts(int type = 0) const;
  QStringList contactsNames() const;
  int addContact(const QString& name);
  bool handleAddContactRequest(const QString& name);
  bool removeContact(const QString& name);
  QStringList GetContactInfo(const QString &pub_name);

  // Shares
  bool createShare(const QString& shareName,
                   const QStringList& admin,
                   const QStringList& readOnly);
  ShareList shares(int type = 0, int filterType = 0) const;
  QDir shareDirRoot(const QString& name) const;
  QDir myFilesDirRoot(const QString& name) const;

  // Tooltip Getters
  QString getContactTooltip(HintLevel level);
  QString getSharesTooltip(HintLevel level);
  QString getLogsTooltip(HintLevel level);
  QString getEmailTooltip(HintLevel level);
  QString getMyFilesTooltip(HintLevel level);

  // Messaging
  bool GetMessages();
  void StartCheckingMessages();
  void StopCheckingMessages();
  bool sendInstantMessage(const QString& txt,
                          const QList<QString>& to,
                          const QString& conversation);
  bool sendInstantFile(const QString& filePath,
                       const QString& txt,
                       const QList<QString>& to,
                       const QString& conversation);

	bool sendEmail(const QString& subject,
                 const QString& message,
                 const QList<QString>& to,
								 const QList<QString>& cc,
								 const QList<QString>& bcc,
                 const QString& conversation);

  // Vault info
  bool PollVaultInfo(QString *chunkstore, boost::uint64_t *offered_space,
                     boost::uint64_t *free_space, QString *ip,
                     boost::uint32_t *port);
  bool IsLocalVaultOwned();

  int SaveSession();
  bs2::connection ConnectToOnFileNetworkStatus(
      const OnFileNetworkStatus::slot_type &slot);

 signals:
  void messageReceived(int type,
                       const QDateTime& time,
                       const QString& from,
                       const QString& msg,
                       const QString& conversation);
  void addedContact(const QString& name);
  void confirmedContact(const QString& name);
  void deletedContact(const QString& name);
  void addedPrivateShare(const QString& name);
  void contactStatusChanged(const QString& from,
                            int status);
  void contactAdditionRequested(const QString& from,
                                const QString& msg);
  void shareReceived(const QString& from,
                     const QString& share_name);
  void shareChanged(const QString& from,
                    const QString& share_name);
  void fileReceived(const QString &sender, const QString &filename,
                    const QString &tag, int sizeLow, int sizeHigh,
                    ClientController::ItemType &type);
  void connectionStatusChanged(int status);
  void systemMessage(const QString& message);
	void emailReceieved(const QString &subject, const QString &conversation,
                      const QString &message, const QString &sender,
                      const QString &theDate);

  private slots:
    // temporary while we emulate message notifications
    void onCheckMessagesCompleted(bool success);

 private:
  explicit ClientController(QObject* parent = 0);
  virtual ~ClientController();
  // receive notifications for IM
  void OnNewMessage(const std::string &msg);
  void OnHelloPing(const std::string &contact_name, const int &status);

  void analyseMessage(const maidsafe::InstantMessage& im);
  CheckForMessagesThread *cfmt_;
};

#endif  // QT_CLIENT_CLIENT_CONTROLLER_H_





