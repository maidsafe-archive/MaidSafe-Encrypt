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

#include "qt/client/client_controller.h"

// qt
#include <QObject>
#include <QStringList>
#include <QDebug>
#include <QTimer>

#include <maidsafe/maidsafe-dht.h>
#include <boost/progress.hpp>
// std
#include <list>
#include <set>
#include <string>
#include <vector>

//local
#include "qt/client/check_for_messages_thread.h"

// core
#include "fs/filesystem.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/privateshares.h"

const int MESSAGE_POLL_TIMEOUT_MS = 3000;

namespace {
  bool contactSortLessThan(const Contact* c1, const Contact* c2) {
    return c1->publicName() < c2->publicName();
  }
}

class ClientController::ClientControllerImpl {
 public:
  ClientControllerImpl() { }
  QTimer messagePollTimer;
};

ClientController* ClientController::instance() {
  static ClientController qtcc;
  return &qtcc;
}

ClientController::ClientController(QObject* parent)
    : QObject(parent)
    , impl_(new ClientControllerImpl) { }

ClientController::~ClientController() {
  delete impl_;
  impl_ = NULL;
}

bool ClientController::Init() {
  return maidsafe::ClientController::getInstance()->Init();
}

void ClientController::StartCheckingMessages() {
  impl_->messagePollTimer.start(MESSAGE_POLL_TIMEOUT_MS);
  connect(&impl_->messagePollTimer, SIGNAL(timeout()),
          this,                     SLOT(checkForMessages()));
}

void ClientController::StopCheckingMessages() {
  impl_->messagePollTimer.stop();
  disconnect(&impl_->messagePollTimer, NULL, this, NULL);
}

void ClientController::shutdown() {
  maidsafe::ClientController::getInstance()->CloseConnection(true);
}

QString ClientController::publicUsername() const {
  return QString::fromStdString(
         maidsafe::SessionSingleton::getInstance()->PublicUsername());
}

bool ClientController::createShare(const QString& shareName,
                                   const QStringList& admin,
                                   const QStringList& readOnly) {
  qDebug() << "createShare:" << shareName << admin << readOnly;
  std::set<std::string> admin_set, ro_set;

  foreach(const QString& s, admin) {
    admin_set.insert(s.toStdString());
  }

  foreach(const QString& s, readOnly) {
    ro_set.insert(s.toStdString());
  }

  int n = maidsafe::ClientController::getInstance()->CreateNewShare(
          shareName.toStdString(), admin_set, ro_set);

  qDebug() << "Add share result: " << n;

  if (n == 0) {
    return true;
  }

  return false;
}

std::list<std::string> ClientController::getShareList(int type,
                                                      int filterType) const {
  std::list<std::string> share_list;

  const int n =
        maidsafe::ClientController::getInstance()->ShareList(
        maidsafe::SortingMode(type), maidsafe::ShareFilter(filterType),
        &share_list);

/* if (n == 0) {
    while (!share_list->empty()) {
      std::string shareName = share_list.front();
      share_list->pop_front();

      QString shareN = shareName;

      Share share(shareN);

      rv.push_back(share);
    }
 }*/

  return share_list;
}

ShareList ClientController::shares(int type, int filterType) const {
  ShareList rv;
  std::list<maidsafe::PrivateShare> ps_list;
  const int n = maidsafe::ClientController::getInstance()->GetShareList(
                &ps_list, maidsafe::SortingMode(type),
                maidsafe::ShareFilter(filterType), "");
  qDebug() << ps_list.size();
  if (n == 0) {
    while (!ps_list.empty()) {
      maidsafe::PrivateShare ps = ps_list.front();
      ps_list.pop_front();

      QString shareName = QString::fromStdString(ps.Name());
      Share share(shareName);

      std::list<maidsafe::ShareParticipants> participants =
                                                      ps.Participants();
      std::list<maidsafe::ShareParticipants>::const_iterator I =
                                                  participants.begin();
      std::list<maidsafe::ShareParticipants>::const_iterator E =
                                                  participants.end();
      for (; I != E; ++I) {
        const QString name = QString::fromStdString(I->id);
        const char role = I->role;
        Share::Permissions permissions = Share::NONE;
        if (role == 'A') {
            permissions = Share::Permissions(Share::READ | Share::WRITE);
        } else if (role == 'R') {
            permissions = Share::READ;
        }
        share.addParticipant(name, permissions);
      }
      rv.push_back(share);
    }
  }

  return rv;
}


QDir ClientController::shareDirRoot(const QString& name) const {
  qDebug() << "ClientController::shareDirRoot:" << name;
  QString pathInMaidsafe = QString("Shares%1Private%2%3")
                          .arg(QDir::separator())
                          .arg(QDir::separator())
                          .arg(name);

#ifdef MAIDSAFE_WIN32
  QString maidsafeRoot = QString("%1:\\").arg(
                         maidsafe::SessionSingleton::getInstance()->WinDrive());
#else
  file_system::FileSystem fs;
  // Path comes back without that last slash
  QString maidsafeRoot = QString::fromStdString(fs.MaidsafeFuseDir() + "/");
#endif

  QString path = maidsafeRoot + pathInMaidsafe;

  QDir dir(path);
  if (!dir.exists()) {
    qWarning() << "share directory doesn't exist:" << path;
  }

  return dir;
}

QDir ClientController::myFilesDirRoot(const QString& name) const {
  qDebug() << "ClientController::myFilesDirRoot:" << name;
  QString pathInMaidsafe = QString("My Files%1%2")
                          .arg(QDir::separator())
                          .arg(name);

#ifdef MAIDSAFE_WIN32
  QString maidsafeRoot = QString("%1:\\").arg(
                         maidsafe::SessionSingleton::getInstance()->WinDrive());
#else
  file_system::FileSystem fs;
  // Path comes back without that last slash
  QString maidsafeRoot = QString::fromStdString(fs.MaidsafeFuseDir() + "/");
#endif

  QString path = maidsafeRoot + pathInMaidsafe;

  QDir dir(path);
  if (!dir.exists()) {
    qWarning() << "share directory doesn't exist:" << path;
  }

  return dir;
}


QStringList ClientController::contactsNames() const {
  std::vector<maidsafe::Contact> contact_list;
  const int n =
      maidsafe::ClientController::getInstance()->ContactList("",
      maidsafe::ALPHA, &contact_list);
  if (n != 0) {
#ifdef DEBUG
    qDebug() << "ClientController::contactNames(): failed to get contacts. Err:"
             << n;
#endif
    return QStringList();
  }

  QStringList rv;
  for (int i = 0; i < contact_list.size(); ++i) {
    rv.push_back(QString::fromStdString(contact_list[i].PublicName()));
  }

  return rv;
}

ContactList ClientController::contacts(int type) const {
  std::vector<maidsafe::Contact> contact_list;
  const int n =
      maidsafe::ClientController::getInstance()->ContactList(
                                    "", maidsafe::SortingMode(type),
                                    &contact_list);
  if (n != 0) {
#ifdef DEBUG
    qDebug() << "ClientController::contacts(): failed to get contacts. Err:"
             << n;
#endif
      return ContactList();
  }

  ContactList rv;
  for (unsigned int i = 0; i < contact_list.size(); ++i) {
    // accessors on maidsafe::Contact are non-const so can't pass in const&
    /*const*/ maidsafe::Contact mcontact = contact_list[i];
    Contact* contact = Contact::fromContact(&mcontact);
    if (mcontact.Confirmed() == 'U')
      contact->setPresence(Presence::INVALID);
    else
      contact->setPresence(Presence::AVAILABLE);

    rv.push_back(contact);
  }

  qSort(rv.begin(), rv.end(), contactSortLessThan);

  return rv;
}

int ClientController::addContact(const QString& name) {
  qDebug() << "ClientController::addContact:" << name;

  // Check that the contact isn't already in the contact list
  maidsafe::mi_contact mic;
  int n = maidsafe::SessionSingleton::getInstance()->
          GetContactInfo(name.toStdString(), &mic);


  if (n == 0) {
    if (mic.pub_name_ == name.toStdString()) {  // Contact already in list
      qDebug() << "Error adding contact. Username already a Contact.";
      return -7;
    }
  }

  return maidsafe::ClientController::getInstance()->
         AddContact(name.toStdString());
}

bool ClientController::removeContact(const QString& name) {
  qDebug() << "ClientController::removeContact:" << name;

  const int n = maidsafe::ClientController::getInstance()->DeleteContact(
                name.toStdString());

  return (n == 0);
}


bool ClientController::sendInstantMessage(const QString& txt,
                                          const QList<QString> &to,
                                          const QString& conversation) {
  qDebug() << "ClientController::sendInstantMessage: " << txt;

  std::vector<std::string> contacts;
  foreach(QString c, to) {
    contacts.push_back(c.toStdString());
  }
  const int n = maidsafe::ClientController::getInstance()->
                SendInstantMessage(txt.toStdString(), contacts,
                conversation.toStdString());

  qDebug() << "ClientController::sendInstantMessage res: " << n;
  return (n == 0);
}

bool ClientController::sendInstantFile(const QString& filePath,
                                       const QString& txt,
                                       const QList<QString>& to,
                                       const QString& conversation) {
  qDebug() << "ClientController::sendInstantFile: " << filePath
           << " -- " << txt;

  file_system::FileSystem fsys;
  std::string rel_filename(fsys.MakeRelativeMSPath(filePath.toStdString()));

#ifdef MAIDSAFE_WIN32
  // trim e.g. C:
  rel_filename.erase(0, 2);
#endif
  qDebug() << "Before Tidy Path:" << rel_filename.c_str();

  rel_filename = base::TidyPath(rel_filename);
  qDebug() << "Tidied Path:" << rel_filename.c_str();

  std::vector<std::string> contacts;
  foreach(QString c, to) {
    contacts.push_back(c.toStdString());
  }
  const int n = maidsafe::ClientController::getInstance()->
                SendInstantFile(&rel_filename, txt.toStdString(), contacts,
                conversation.toStdString());
  qDebug() << "ClientController::sendInstantFile res: " << n;

  return (n == 0);
}

bool ClientController::PollVaultInfo(QString *chunkstore,
                                     boost::uint64_t *offered_space,
                                     boost::uint64_t *free_space,
                                     QString *ip,
                                     boost::uint32_t *port) {
  std::string s_chunkstore;
  std::string s_ip;
  bool b = maidsafe::ClientController::getInstance()->PollVaultInfo(
           &s_chunkstore, offered_space, free_space, &s_ip, port);
  if (b) {
    *chunkstore = QString::fromStdString(s_chunkstore);
    *ip = QString::fromStdString(s_ip);
    return true;
  }

  return false;
}

bool ClientController::IsLocalVaultOwned() {
  // For local version returns always false. Use the return true to check for
  // other behaviour.

  //  return true;
  return maidsafe::ClientController::getInstance()->IsLocalVaultOwned();
}

void ClientController::checkForMessages() {
  // Check for messages only when public username is set

  if (publicUsername().isEmpty())
    return;

  CheckForMessagesThread* cfmt = new CheckForMessagesThread(this);

  connect(cfmt, SIGNAL(completed(bool)),
          this, SLOT(onCheckMessagesCompleted(bool)));

  cfmt->start();

  StopCheckingMessages();

  /*if (!maidsafe::ClientController::getInstance()->GetMessages()) {
    if (maidsafe::SessionSingleton::getInstance()->ConnectionStatus() != 1) {
      int one(1);
      // modify CC online status
      maidsafe::SessionSingleton::getInstance()->SetConnectionStatus(one);
      // signal for change of icon
      emit connectionStatusChanged(one);
      return;
    }
  } else {
    if (maidsafe::SessionSingleton::getInstance()->ConnectionStatus() == 1) {
      int zero(0);
      // modify CC online status
      maidsafe::SessionSingleton::getInstance()->SetConnectionStatus(zero);
      // signal for change of icon
      emit connectionStatusChanged(zero);
      return;
    }
  }
  std::list<maidsafe::InstantMessage> msgs;
  int n = maidsafe::ClientController::getInstance()
                ->GetInstantMessages(&msgs);


  if (n != 0)
    return;

  std::list<maidsafe::InstantMessage> temp = msgs;
  while (!temp.empty()) {
      analyseMessage(temp.front());
      temp.pop_front();
  }*/
}

void ClientController::onCheckMessagesCompleted(bool success){
    if (!success) {
    if (maidsafe::SessionSingleton::getInstance()->ConnectionStatus() != 1) {
      int one(1);
      // modify CC online status
      maidsafe::SessionSingleton::getInstance()->SetConnectionStatus(one);
      // signal for change of icon
      emit connectionStatusChanged(one);
      return;
    }
  } else {
    if (maidsafe::SessionSingleton::getInstance()->ConnectionStatus() == 1) {
      int zero(0);
      // modify CC online status
      maidsafe::SessionSingleton::getInstance()->SetConnectionStatus(zero);
      // signal for change of icon
      emit connectionStatusChanged(zero);
      return;
    }
  }
  std::list<maidsafe::InstantMessage> msgs;
  int n = maidsafe::ClientController::getInstance()
                ->GetInstantMessages(&msgs);

  if (n != 0)
    return;

  std::list<maidsafe::InstantMessage> temp = msgs;
  while (!temp.empty()) {
      analyseMessage(temp.front());
      temp.pop_front();
  }
  StartCheckingMessages();
}

int ClientController::analyseMessage(const maidsafe::InstantMessage& im) {
  boost::progress_timer t;
  MessageType type = TEXT;
  int n = 0;
  if (im.has_contact_notification()) {
    qDebug() << "HANDLING Contact Notification";
    maidsafe::ContactNotification cn = im.contact_notification();
    maidsafe::ContactInfo ci;
    if (cn.has_contact())
      ci = cn.contact();

    switch (cn.action()) {
      // ADD REQUEST - we have requested to add a user
      case 0:
            {
              qDebug() << "HANDLING AddContactRequest";

              emit addedContact(QString::fromStdString(im.sender()), im);
              type = CONTACT_REQUEST;

              break;
            }
      // ADD RESPONSE - a user has responded to our add request
      case 1:
            {
              qDebug() << "HANDLING AddContactResponse";
              n = maidsafe::ClientController::getInstance()->
                                      HandleAddContactResponse(ci, im.sender());

              if (n == 0) {
                emit confirmedContact(QString::fromStdString(im.sender()));
                type = CONTACT_RESPONSE;
              }
              break;
            }
      // DELETE CONTACT - a contact has deleted you from their list
      case 2:
            {
              qDebug() << "HANDLING Deletecontact";
              n = maidsafe::ClientController::getInstance()->
                                   HandleDeleteContactNotification(im.sender());

              qDebug() << "HANDLING Deletecontact result " << n;
              if (n == 0) {
                emit deletedContact(QString::fromStdString(im.sender()));
                type = CONTACT_DELETE;
              }
              break;
            }
    }
  } else if (im.has_instantfile_notification()) {
    emit fileReceived(im);
    type = FILE;
  } else if (im.has_privateshare_notification()) {
    // we have added a new private share
    // \TODO what about someone else adding us to one og their shares?
    n = maidsafe::ClientController::getInstance()->
                    HandleReceivedShare(im.privateshare_notification(), "");
    if (n == 0) {
      maidsafe::PrivateShareNotification psn = im.privateshare_notification();
      emit addedPrivateShare(QString::fromStdString(psn.name()));
      type = SHARE;
    }
  }

  QDateTime time = QDateTime::currentDateTime();
  if (im.has_date()) {
    time = QDateTime::fromTime_t(im.date());
  }
  const QString message = QString::fromStdString(im.message());
  const QString sender = QString::fromStdString(im.sender());
  const QString conversation = QString::fromStdString(im.conversation());

  emit messageReceived(type, time, sender, message, conversation);
   printf("Ansa %f", t.elapsed());

  return n;

}

int ClientController::SaveSession() {
  return maidsafe::ClientController::getInstance()->SaveSession();
}

bool ClientController::ChangeUsername(const std::string &new_username) {
  return maidsafe::ClientController::getInstance()->ChangeUsername(new_username);
}

bool ClientController::ChangePin(const std::string &new_pin) {
  return maidsafe::ClientController::getInstance()->ChangePin(new_pin);
}

bool ClientController::ChangePassword(const std::string &new_password) {
  return maidsafe::ClientController::getInstance()->ChangePassword(new_password);
}

bool ClientController::CreatePublicUsername(const std::string &public_username) {
  return maidsafe::ClientController::getInstance()->CreatePublicUsername(public_username);
}

bool ClientController::CreateUser(const std::string &username,
                                  const std::string &pin,
                                  const std::string &password,
                                  const maidsafe::VaultConfigParameters &vcp) {
  return maidsafe::ClientController::getInstance()->CreateUser(
                          username, pin, password, vcp);
}

int ClientController::CheckUserExists(const std::string &username,
                                      const std::string &pin,
                                      maidsafe::DefConLevels level) {
  return maidsafe::ClientController::getInstance()->CheckUserExists(
                                    username, pin, level);
}

int ClientController::CreateNewShare(const std::string &name,
                     const std::set<std::string> &admins,
                     const std::set<std::string> &readonlys) {
  return maidsafe::ClientController::getInstance()->CreateNewShare(
                                    name, admins, readonlys);
}

bool ClientController::ValidateUser(const std::string &password){
  return maidsafe::ClientController::getInstance()->ValidateUser(password);
}

int ClientController::ConversationList(std::list<std::string> *conversations){
  return maidsafe::SessionSingleton::getInstance()->ConversationList(conversations);
}

int ClientController::AddConversation(const std::string &id){
  return maidsafe::SessionSingleton::getInstance()->AddConversation(id);
}

int ClientController::RemoveConversation(const std::string &id){
  return maidsafe::SessionSingleton::getInstance()->RemoveConversation(id);
}

int ClientController::ConversationExits(const std::string &id){
  return maidsafe::SessionSingleton::getInstance()->ConversationExits(id);
}

void ClientController::ClearConversations(){
  maidsafe::SessionSingleton::getInstance()->ClearConversations();
}

int ClientController::GetContactInfo(const std::string &pub_name,
                                     maidsafe::mi_contact *mic) {
  return maidsafe::SessionSingleton::getInstance()->GetContactInfo(pub_name, mic);
}






