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
#include <QDebug>
#include <QTimer>

#include <maidsafe/maidsafe-dht.h>
#include <boost/progress.hpp>
#include <boost/lexical_cast.hpp>

// std
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

// core
#include "fs/filesystem.h"
#include "maidsafe/utils.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/privateshares.h"

const int MESSAGE_POLL_TIMEOUT_MS = 3000;

namespace {
  bool contactSortLessThan(const Contact* c1, const Contact* c2) {
    return c1->publicName() < c2->publicName();
  }
}

ClientController* ClientController::instance() {
  static ClientController qtcc;
  return &qtcc;
}

ClientController::ClientController(QObject* parent)
    : QObject(parent),
      cfmt_(NULL) { }

ClientController::~ClientController() { }

bool ClientController::Init() {
  boost::uint8_t K(4);
  int init_result = maidsafe::ClientController::getInstance()->Init(K);
  if (init_result == 0) {
    maidsafe::ClientController::getInstance()->RegisterImNotifiers(
        boost::bind(&ClientController::OnNewMessage, this, _1),
        boost::bind(&ClientController::OnHelloPing, this, _1, _2));
  }
  return init_result;
}

void ClientController::StartCheckingMessages() {
  cfmt_ = new CheckForMessagesThread(this);
  cfmt_->set_interval(kCheckForMessagesInterval);
  cfmt_->set_started(true);
  connect(cfmt_, SIGNAL(completed(bool)),
          this,  SLOT(onCheckMessagesCompleted(bool)));
  cfmt_->start();
}

void ClientController::StopCheckingMessages() {
  cfmt_->set_started(false);
  cfmt_->terminate();
  cfmt_->wait();
  disconnect(cfmt_, NULL, this, NULL);
}

void ClientController::shutdown() {
  maidsafe::ClientController::getInstance()->CloseConnection(true);
  maidsafe::ClientController::getInstance()->Destroy();
}

QString ClientController::publicUsername() const {
  return QString::fromStdString(
         maidsafe::SessionSingleton::getInstance()->PublicUsername());
}

bool ClientController::getPendingOps(QList<PendingOps> &ops) {
  //array<pendingOps> pending;
  //maidsafe::PendingOps po;
  //get pendingOps from maisafe and convert to QT PendingOps
  //maidsafe::ClientController::getInstance()->getPendingOps(pending);


  PendingOps op;
  op.name = "testName.txt";
  op.transBytes = 1583;
  op.totalBytes = 10000;

  ops.append(op);
  return false;
}

int ClientController::AddInstantFile(const QString &sender, const QString &filename,
                   const QString &tag,
                   int sizeLow, int sizeHigh,
                   const ClientController::ItemType &ityp,
                   const QString &s){

  maidsafe::InstantFileNotification ifn;
  ifn.set_filename(filename.toStdString());

  maidsafe::MetaDataMap mdm;
  mdm.set_tag(tag.toStdString());
  mdm.set_file_size_high(sizeHigh);
  mdm.set_file_size_low(sizeLow);
  std::string ser_mdm;
  mdm.SerializeToString(&ser_mdm);
  ifn.set_ser_mdm(ser_mdm);

  int n = maidsafe::ClientController::getInstance()->
          AddInstantFile(ifn, s.toStdString());

  return n;
}

bool ClientController::createShare(const QString &shareName,
                                   const QStringList &admin,
                                   const QStringList &readOnly) {
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

ShareList ClientController::shares(int type, int filterType) const {
  ShareList rv;
  std::list<maidsafe::PrivateShare> ps_list;
  const int n = maidsafe::ClientController::getInstance()->GetShareList(
                    maidsafe::SortingMode(type),
                    maidsafe::ShareFilter(filterType), "", &ps_list);
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

#ifdef PD_WIN32
  QString maidsafeRoot = QString("%1:\\").arg(
                         maidsafe::SessionSingleton::getInstance()->WinDrive());
#else
  // Path comes back without that last slash
  QString maidsafeRoot = QString::fromStdString(file_system::MaidsafeFuseDir(
      maidsafe::SessionSingleton::getInstance()->SessionName()).string() + "/");
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

#ifdef PD_WIN32
  QString maidsafeRoot = QString("%1:\\").arg(
                         maidsafe::SessionSingleton::getInstance()->WinDrive());
#else
  // Path comes back without that last slash
  QString maidsafeRoot = QString::fromStdString(file_system::MaidsafeFuseDir(
      maidsafe::SessionSingleton::getInstance()->SessionName()).string() + "/");
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
  const int n = maidsafe::ClientController::getInstance()->ContactList("",
                maidsafe::ALPHA, &contact_list);
  if (n != 0) {
#ifdef DEBUG
    qDebug() << "ClientController::contactNames(): failed to get contacts. Err:"
             << n;
#endif
    return QStringList();
  }

  QStringList rv;
  for (size_t i = 0; i < contact_list.size(); ++i) {
    rv.push_back(QString::fromStdString(contact_list[i].PublicName()));
  }

  return rv;
}

ContactList ClientController::contacts(int type) const {
  std::vector<maidsafe::Contact> contact_list;
  const int n = maidsafe::ClientController::getInstance()->ContactList(
                "", maidsafe::SortingMode(type), &contact_list);
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
    maidsafe::Contact mcontact = contact_list[i];
    Contact* contact = Contact::fromContact(QString::fromStdString(mcontact.PublicName()));
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

bool ClientController::handleAddContactRequest(const QString& name) {
  maidsafe::mi_contact mic;
  int n = maidsafe::SessionSingleton::getInstance()->
          GetContactInfo(name.toStdString(), &mic);

  maidsafe::ContactInfo ci;

  ci.set_birthday(mic.birthday_);
  ci.set_city(mic.birthday_);
  ci.set_country(mic.country_);
  std::string str(1, mic.gender_);
  ci.set_gender(str);
  ci.set_language(mic.language_);
  ci.set_name(mic.full_name_);
  ci.set_office_number(mic.office_phone_);

  n = maidsafe::ClientController::getInstance()->
      HandleAddContactRequest(ci, name.toStdString());

  if (n == 0)
    return true;
  else
    return false;
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

bool ClientController::sendEmail(const QString& subject,
                        const QString& message,
                        const QList<QString>& to,
                        const QList<QString>& cc,
                        const QList<QString>& bcc,
                        const QString& conversation) {
  qDebug() << "ClientController::sendEmail: " << subject;

  std::vector<std::string> contacts, stdcc, stdbcc;
  foreach(QString c, to) {
    contacts.push_back(c.toStdString());
  }
  foreach(QString c, cc) {
    stdcc.push_back(c.toStdString());
  }
  foreach(QString c, bcc) {
    stdbcc.push_back(c.toStdString());
  }
  const int n = maidsafe::ClientController::getInstance()->
              SendEmail(subject.toStdString(), message.toStdString(), contacts,
              stdcc, stdbcc, conversation.toStdString());

  return (n == 0);
}

bool ClientController::sendInstantFile(const QString& filePath,
                                       const QString& txt,
                                       const QList<QString>& to,
                                       const QString& conversation) {
  qDebug() << "ClientController::sendInstantFile: " << filePath
           << " -- " << txt;

  std::string rel_filename(file_system::MakeRelativeMSPath(
      filePath.toStdString(),
      maidsafe::SessionSingleton::getInstance()->SessionName()).string());

#ifdef PD_WIN32
  // trim e.g. C:
  rel_filename.erase(0, 2);
#endif
  qDebug() << "Before Tidy Path:" << rel_filename.c_str();

  rel_filename = maidsafe::TidyPath(rel_filename);
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

bool ClientController::Logout() {
  return maidsafe::ClientController::getInstance()->Logout();
}

char ClientController::DriveLetter() {
  return maidsafe::ClientController::getInstance()->DriveLetter();
}

bool ClientController::IsLocalVaultOwned() {
  // For local version returns always false. Use the return true to check for
  // other behaviour.

  //  return true;
  return maidsafe::ClientController::getInstance()->IsLocalVaultOwned();
}

bool ClientController::GetMessages() {
  return maidsafe::ClientController::getInstance()->GetMessages();
}

void ClientController::onCheckMessagesCompleted(bool) {
  std::list<maidsafe::InstantMessage> msgs;
  int n = maidsafe::ClientController::getInstance()->GetInstantMessages(&msgs);

  if (n != 0)
    return;

  std::list<maidsafe::InstantMessage> temp = msgs;
  while (!temp.empty()) {
    analyseMessage(temp.front());
    temp.pop_front();
  }
}

void ClientController::analyseMessage(const maidsafe::InstantMessage& im) {
  boost::progress_timer t;
  int type = int(TEXT);
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

              emit addedContact(QString::fromStdString(im.sender()));
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
    maidsafe::InstantFileNotification ifn = im.instantfile_notification();
    maidsafe::MetaDataMap sent_mdm;
    sent_mdm.ParseFromString(ifn.ser_mdm());

    maidsafe::ItemType mSafeType = sent_mdm.type();
    ClientController::ItemType ityp;
    switch (mSafeType) {
    case maidsafe::DIRECTORY:
      ityp = DIRECTORY;
      break;
    case maidsafe::REGULAR_FILE:
      ityp = REGULAR_FILE;     
      break;
    case maidsafe::SMALL_FILE:
      ityp = SMALL_FILE;     
      break;
    case maidsafe::EMPTY_FILE:
      ityp = EMPTY_FILE;     
      break;
    case maidsafe::LOCKED_FILE:
      ityp = LOCKED_FILE;      
      break;
    case maidsafe::EMPTY_DIRECTORY:
      ityp = EMPTY_DIRECTORY;     
      break;
    case maidsafe::LINK:
      ityp = LINK;      
      break;
    case maidsafe::MAIDSAFE_CHUNK:
      ityp = MAIDSAFE_CHUNK;      
      break;
    case maidsafe::NOT_FOR_PROCESSING:
      ityp = NOT_FOR_PROCESSING;      
      break;
    case maidsafe::UNKNOWN:
      ityp = UNKNOWN;     
      break;
    default:
      ityp = UNKNOWN;
      break;
  }

    int sizeLow = sent_mdm.file_size_low();
    int sizeHigh = sent_mdm.file_size_high();
    QString tag = QString::fromStdString(sent_mdm.tag());

    emit fileReceived(QString::fromStdString(im.sender()),
                      QString::fromStdString(ifn.filename()),
                      tag, sizeLow, sizeHigh, ityp);
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
  } else if (im.has_email_notification()) {
    // TODO(Stephen) :: emit signal to inform GUI of new email and
    // woo only qt stuff from here :)
    QDateTime theDate = QDateTime::currentDateTime();
    theDate.setTime_t(im.date());
    QString date = theDate.toString("dd/MM/yyyy hh:mm:ss");

    emit emailReceieved(QString::fromStdString(im.subject()), 
                        QString::fromStdString(im.conversation()),
                        QString::fromStdString(im.message()),
                        QString::fromStdString(im.sender()),
                        date);
    type = EMAIL;
  }

  QDateTime time = QDateTime::currentDateTime();
  if (im.has_date()) {
    time = QDateTime::fromTime_t(im.date());
  }
  const QString message = QString::fromStdString(im.message());
  const QString sender = QString::fromStdString(im.sender());
  const QString conversation = QString::fromStdString(im.conversation());

  emit messageReceived(type, time, sender, message, conversation);
//  printf("Ansa %f", t.elapsed());

//  return n;
}

int ClientController::SaveSession() {
  return maidsafe::ClientController::getInstance()->SaveSession();
}

bool ClientController::ChangeUsername(const std::string &new_username) {
  return maidsafe::ClientController::getInstance()->
         ChangeUsername(new_username);
}

bool ClientController::ChangePin(const std::string &new_pin) {
  return maidsafe::ClientController::getInstance()->ChangePin(new_pin);
}

bool ClientController::ChangePassword(const std::string &new_password) {
  return maidsafe::ClientController::getInstance()->
         ChangePassword(new_password);
}

bool ClientController::CreatePublicUsername(const std::string &pub_username) {
  return maidsafe::ClientController::getInstance()->
         CreatePublicUsername(pub_username);
}

bool ClientController::CreateUser(const QString &username,
                                  const QString &pin,
                                  const QString &password,
                                  const int &vaultType,
                                  const QString &space,
                                  const QString &port,
                                  const QString &directory) {
  std::string username_ = username.toStdString();
  std::string pin_ = pin.toStdString();
  std::string password_ = password.toStdString();
  std::string space_ = space.toStdString();
  std::string port_ = port.toStdString();

  maidsafe::VaultConfigParameters vcp;
  vcp.vault_type = vaultType;
  vcp.space = boost::lexical_cast<boost::uint32_t>(space_);
  vcp.port = boost::lexical_cast<boost::uint32_t>(port_);
  vcp.directory = directory.toStdString();

  return maidsafe::ClientController::getInstance()->CreateUser(
                          username_, pin_, password_, vcp);
}

bool ClientController::CheckUserExists(const std::string &username,
                                      const std::string &pin,
                                      DefConLevel level) {
  
maidsafe::DefConLevels defCon;                                     
if (level == kDefCon1) {
  defCon = maidsafe::kDefCon1;
}
else if(level == kDefCon2) {
  defCon = maidsafe::kDefCon2;
}
else {
  defCon = maidsafe::kDefCon3;
}

  bool result = true;
  int rc = maidsafe::ClientController::getInstance()->CheckUserExists(
                                    username, pin, defCon);

  if (rc == maidsafe::kUserDoesntExist)
    result = true;
  else
    result = false;    
  return result;
}

int ClientController::CreateNewShare(const std::string &name,
                                     const std::set<std::string> &admins,
                                     const std::set<std::string> &readonlys) {
  return maidsafe::ClientController::getInstance()->CreateNewShare(
                                    name, admins, readonlys);
}

bool ClientController::ValidateUser(const std::string &password) {
  return maidsafe::ClientController::getInstance()->ValidateUser(password);
}

int ClientController::ConversationList(std::list<std::string> *conversations) {
  return maidsafe::SessionSingleton::getInstance()->
         ConversationList(conversations);
}

int ClientController::AddConversation(const std::string &id) {
  return maidsafe::SessionSingleton::getInstance()->AddConversation(id);
}

int ClientController::RemoveConversation(const std::string &id) {
  return maidsafe::SessionSingleton::getInstance()->RemoveConversation(id);
}

int ClientController::ConversationExits(const std::string &id) {
  return maidsafe::SessionSingleton::getInstance()->ConversationExits(id);
}

void ClientController::ClearConversations() {
  maidsafe::SessionSingleton::getInstance()->ClearConversations();
}

QStringList ClientController::GetContactInfo(const QString &pub_name) {  
  maidsafe::mi_contact mic;
  maidsafe::SessionSingleton::getInstance()->GetContactInfo(pub_name.toStdString(), &mic);

  QStringList contact;
  std::string gender(1, mic.gender_);
  std::stringstream ss;
  std::string phone;
  ss << mic.office_phone_;
  ss >> phone;

  contact << QString::fromStdString(mic.birthday_) << QString::fromStdString(mic.city_) <<
    QString::fromStdString(mic.full_name_) << QString::fromStdString(gender) << 
    QString::fromStdString(phone) << QString::fromStdString(mic.pub_name_);

  return contact;
}

int ClientController::getattr(const QString &path, QString &lastModified, QString &fileSize) {
  std::string ser_mdm;
  maidsafe::MetaDataMap mdm;
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  int result = maidsafe::ClientController::getInstance()->getattr(the_path, &ser_mdm);
  mdm.ParseFromString(ser_mdm);

  QDateTime *mod = new QDateTime;
  int linuxtime = mdm.last_modified();
  mod->setTime_t(linuxtime);

  lastModified = mod->toString("dd/MM/yyyy hh:mm");
  int size = mdm.file_size_low();

  double kbSize = ceil(static_cast<double>(size / 1024));

  std::string s = boost::lexical_cast<std::string>(kbSize);
  fileSize = QString::fromStdString(s);
  return result;
}
int ClientController::readdir(const QString &path,  // NOLINT
                              std::map<std::string,
                                       ItemType> *children) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  std::map<std::string, maidsafe::ItemType> children1;
  int result = maidsafe::ClientController::getInstance()->readdir(the_path, &children1);

  while (!children1.empty()) {
    std::string s = children1.begin()->first;
    maidsafe::ItemType ityp = children1.begin()->second;

  switch (ityp) {
    case maidsafe::DIRECTORY:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, DIRECTORY));
      break;
    case maidsafe::REGULAR_FILE:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, REGULAR_FILE));      
      break;
    case maidsafe::SMALL_FILE:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, SMALL_FILE));      
      break;
    case maidsafe::EMPTY_FILE:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, EMPTY_FILE));      
      break;
    case maidsafe::LOCKED_FILE:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, LOCKED_FILE));      
      break;
    case maidsafe::EMPTY_DIRECTORY:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, EMPTY_DIRECTORY));     
      break;
    case maidsafe::LINK:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, LINK));      
      break;
    case maidsafe::MAIDSAFE_CHUNK:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, MAIDSAFE_CHUNK));      
      break;
    case maidsafe::NOT_FOR_PROCESSING:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, NOT_FOR_PROCESSING));      
      break;
    case maidsafe::UNKNOWN:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, UNKNOWN));      
      break;
    default:
      children->insert(std::pair<std::string, ClientController::ItemType>(
      s, UNKNOWN));
      break;
  }

  children1.erase(children1.begin());
  }

  return result;
}
int ClientController::read(const QString &path) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  return maidsafe::ClientController::getInstance()->read(the_path);
}
int ClientController::write(const QString &path) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  return maidsafe::ClientController::getInstance()->write(the_path);
}
int ClientController::rename(const QString &path,
                             const QString &path2) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  std::string the_path2(maidsafe::TidyPath(path2.toStdString()));
  return maidsafe::ClientController::getInstance()->rename(the_path,
                                                           the_path2);
}
int ClientController::mkdir(const QString &path) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  return maidsafe::ClientController::getInstance()->mkdir(the_path);
}
int ClientController::rmdir(const QString &path) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  return maidsafe::ClientController::getInstance()->rmdir(the_path);
}
int ClientController::mknod(const QString &path) {
  std::string the_path(maidsafe::TidyPath(path.toStdString()));
  return maidsafe::ClientController::getInstance()->mknod(the_path);
}

void ClientController::OnNewMessage(const std::string &msg) {
  maidsafe::InstantMessage im;
  if (im.ParseFromString(msg)) {
    analyseMessage(im);
  }
}

QString ClientController::getContactTooltip(HintLevel level) {
  if (level == SMALL) {
    return "Contacts";
  } else if (level == FULL) {
    return "Contacts : Use This to communicate and share files with your friends";
  }
  return "";
}

QString ClientController::getSharesTooltip(HintLevel level) {
  if (level == SMALL) {
    return "Shares";
  } else if (level == FULL) {
    return "Shares : Use This Tab to create and modify shares";
  }
  return "";
}

QString ClientController::getLogsTooltip(HintLevel level) {
  if (level == SMALL) {
    return "Logs";
  } else if (level == FULL) {
    return "Logs : Use This Tab to View PD Information";
  }
  return "";
}
QString ClientController::getEmailTooltip(HintLevel level) {
  if (level == SMALL) {
    return "Email";
  } else if (level == FULL) {
    return "Email : Use This Tab to view and reply to your emails";
  }
  return "";
}
QString ClientController::getMyFilesTooltip(HintLevel level) {
  if (level == SMALL) {
    return "My Files";
  } else if (level == FULL) {
    return "My Files : Use This Tab to manage your protected PD Files";
  }
  return "";
}

void ClientController::OnHelloPing(const std::string &contact_name,
        const int &status) {
  // TODO(Team): update GUI
  printf("contact %s with status %d\n", contact_name.c_str(), status);
}
