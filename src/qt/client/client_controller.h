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

#include <string>

// core
#include "maidsafe/client/clientinterface.h"
#include "maidsafe/client/clientcontroller.h"

// local
#include "qt/client/share.h"
#include "qt/client/profile.h"
#include "qt/client/presence.h"
#include "qt/client/contact.h"



// Wrapper for maidsafe::ClientController
/*!
    Implements the ClientController notification interface and wraps up
    the ClientController methods in a Qt style API.

    The ClientController class, in conjunction with the other classes in
    qt/client, act as a layer between the Qt gui world and the maidsafe
    world.
*/
class ClientController : public QObject {
  Q_OBJECT
 public:
  enum MessageType {
      TEXT,               // Instant message received from someone
      SHARE,              // Someone has shared something
      FILE,               // Someone has sent a file
      CONTACT_REQUEST,    // Someone has requested to add us
      CONTACT_RESPONSE,   // Someone has responed to our request
      CONTACT_DELETE,     // Someone has deleted us from their list
      INVITE              // To invite someone to a conversation
  };

  static ClientController* instance();
  void shutdown();
  bool Init();

  QString publicUsername() const;

  // Contacts
  ContactList contacts(int type = 0) const;
  QStringList contactsNames() const;
  int addContact(const QString& name);
  bool removeContact(const QString& name);


  // Shares
  bool createShare(const QString& shareName,
                   const QStringList& admin,
                   const QStringList& readOnly);
  ShareList shares(int type = 0, int filterType = 0) const;
  std::list<std::string> getShareList(int type = 0, int filterType = 0) const;
  QDir shareDirRoot(const QString& name) const;
  QDir myFilesDirRoot(const QString& name) const;


  // Messaging
  void StartCheckingMessages();
  void StopCheckingMessages();
  bool sendInstantMessage(const QString& txt,
                          const QList<QString>& to,
                          const QString& conversation);
  bool sendInstantFile(const QString& filePath,
                       const QString& txt,
                       const QList<QString>& to,
                       const QString& conversation);

  // Vault info
  bool PollVaultInfo(QString *chunkstore, boost::uint64_t *offered_space,
                     boost::uint64_t *free_space, QString *ip,
                     boost::uint32_t *port);
  bool IsLocalVaultOwned();

  int SaveSession();

 signals:
  void messageReceived(ClientController::MessageType type,
                       const QDateTime& time,
                       const QString& from,
                       const QString& msg,
                       const QString& conversation);
  void addedContact(const QString& name, const maidsafe::InstantMessage& im);
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
  void fileReceived(const maidsafe::InstantMessage& im);
  void connectionStatusChanged(int status);
  void systemMessage(const QString& message);

  private slots:
    // temporary while we emulate message notifications
    void checkForMessages();

 private:
  explicit ClientController(QObject* parent = 0);
  virtual ~ClientController();

  int analyseMessage(const maidsafe::InstantMessage& im);
  class ClientControllerImpl;
  ClientControllerImpl* impl_;
};

#endif  // QT_CLIENT_CLIENT_CONTROLLER_H_





