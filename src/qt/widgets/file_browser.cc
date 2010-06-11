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
 *  Created on: Jan 06, 2010
 *      Author: Stephen Alexander
 */

#include "qt/widgets/file_browser.h"

#include <QDebug>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QMouseEvent>
#include <QUrl>

#include <map>
#include <string>
#include <math.h>
#include <iostream>
#include <fstream>
#ifdef PD_WIN32
#include <windows.h>
#include <shellapi.h>
#endif

#include "maidsafe/utils.h"
#include "fs/filesystem.h"
#include "qt/client/client_controller.h"
#include "qt/client/make_directory_thread.h"
#include "qt/client/read_file_thread.h"
#include "qt/client/remove_dir_thread.h"
#include "qt/client/rename_file_thread.h"
#include "qt/client/save_file_thread.h"
#include "qt/client/user_space_filesystem.h"

namespace fs = boost::filesystem;

FileBrowser::FileBrowser(QWidget* parent) : QDialog(parent), init_(false) {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/64/64/maidsafe-triangle.png"));
  this->setWindowFlags(Qt::WindowMinMaxButtonsHint | Qt::WindowCloseButtonHint);
  // theWatcher_ = new QFileSystemWatcher;
  ui_.driveTreeWidget->setAcceptDrops(true);
  ui_.driveTreeWidget->viewport()->installEventFilter(this);
  ui_.driveListWidget->installEventFilter(this);

  createAndConnectActions();

  connect(ui_.driveTreeWidget, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)),
          this,            SLOT(onItemDoubleClicked(QTreeWidgetItem*, int)));

  connect(ui_.driveTreeWidget, SIGNAL(itemPressed(QTreeWidgetItem*, int)),
          this,            SLOT(onMousePressed(QTreeWidgetItem*, int)));

  connect(ui_.treeViewTreeWidget, SIGNAL(itemExpanded(QTreeWidgetItem*)),
          this,            SLOT(onItemExpanded(QTreeWidgetItem*)));

  connect(ui_.treeViewTreeWidget, SIGNAL(itemPressed(QTreeWidgetItem*, int)),
          this,            SLOT(onFolderItemPressed(QTreeWidgetItem*, int)));

  connect(ui_.backButton, SIGNAL(clicked(bool)),
          this,           SLOT(onBackClicked(bool)));

  connect(ui_.driveListWidget, SIGNAL(itemDoubleClicked(QListWidgetItem*)),
          this,           SLOT(onListItemDoubleClicked(QListWidgetItem*)));

  connect(ui_.driveListWidget, SIGNAL(itemPressed(QListWidgetItem*)),
          this,           SLOT(onIconMousePressed(QListWidgetItem*)));
}

FileBrowser::~FileBrowser() {
  reset();
}

void FileBrowser::createAndConnectActions() {
  menu = new QMenu(this);

  openFile = new QAction(tr("Open"), this);
  openWith = new QAction(tr("Open With.."), this);
  sendFile = new QAction(tr("Send"), this);
  cutFile = new QAction(tr("Cut"), this);
  copyFile = new QAction(tr("Copy"), this);
  deleteFile = new QAction(tr("Delete"), this);
  renameFile = new QAction(tr("Rename"), this);
  saveFile = new QAction(tr("Save"), this);

  menu->addAction(openFile);
  menu->addAction(openWith);
  menu->addAction(saveFile);
  menu->addSeparator();
//  menu->addAction(cutFile);
//  menu->addAction(copyFile);
//  menu->addSeparator();
  menu->addAction(deleteFile);
  menu->addAction(renameFile);
  menu->addAction(sendFile);

  connect(openFile, SIGNAL(triggered()),
          this,        SLOT(onOpenFileClicked()));

  connect(openWith, SIGNAL(triggered()),
          this,        SLOT(onOpenWithClicked()));

  connect(sendFile, SIGNAL(triggered()),
          this,        SLOT(onSendFileClicked()));

  connect(cutFile, SIGNAL(triggered()),
          this,        SLOT(onCutFileClicked()));

  connect(copyFile, SIGNAL(triggered()),
          this,        SLOT(onCopyFileClicked()));

  connect(deleteFile, SIGNAL(triggered()),
          this,        SLOT(onDeleteFileClicked()));

  connect(renameFile, SIGNAL(triggered()),
          this,        SLOT(onRenameFileClicked()));

  connect(saveFile, SIGNAL(triggered()),
          this,        SLOT(onSaveFileClicked()));

  menu2 = new QMenu(this);
  viewGroup = new QActionGroup(this);
  sortGroup = new QActionGroup(this);
  view = new QMenu(tr("View"), this);
  sort = new QMenu(tr("Sort By"), this);

  newFolder = new QAction(tr("New Folder"), this);

  /*tilesMode = new QAction(tr("Tiles"), viewGroup);
  tilesMode->setCheckable(true);*/
  detailMode = new QAction(tr("Details"), viewGroup);
  detailMode->setCheckable(true);
  detailMode->setChecked(true);
  listMode = new QAction(tr("List"), viewGroup);
  listMode->setCheckable(true);
  bigListMode = new QAction(tr("Big List"), viewGroup);
  bigListMode->setCheckable(true);
  iconMode = new QAction(tr("Icons"), viewGroup);
  iconMode->setCheckable(true);

  nameSort = new QAction(tr("Name"), sortGroup);
  sizeSort = new QAction(tr("Size"), sortGroup);
  typeSort = new QAction(tr("Type"), sortGroup);
  dateSort = new QAction(tr("Date Modified"), sortGroup);

  // view->addAction(tilesMode);
  view->addAction(detailMode);
  view->addAction(bigListMode);
  view->addAction(listMode);
  view->addAction(iconMode);
  sort->addAction(nameSort);
  sort->addAction(sizeSort);
  sort->addAction(typeSort);
  sort->addAction(dateSort);

  menu2->addMenu(view);
  menu2->addMenu(sort);
  menu2->addSeparator();
  menu2->addAction(newFolder);

  connect(newFolder, SIGNAL(triggered()),
          this,        SLOT(onNewFolderClicked()));

  connect(viewGroup, SIGNAL(triggered(QAction*)),
          this,        SLOT(onViewGroupClicked(QAction*)));

  connect(sortGroup, SIGNAL(triggered(QAction*)),
          this,        SLOT(onSortGroupClicked(QAction*)));
}

void FileBrowser::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
    ui_.driveListWidget->setVisible(false);
    viewMode_ = DETAIL;

    rootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                    ClientController::instance()->SessionName()).string()+"/");

    qDebug() << rootPath_;

    currentDir_ = "/";
    currentTreeDir_ = "/";
    populateDirectory("/");
    createTreeDirectory("/");
    ui_.driveTreeWidget->header()->setResizeMode(QHeaderView::Interactive);
    ui_.driveTreeWidget->header()->setStretchLastSection(true);
    ui_.driveTreeWidget->setSortingEnabled(true);
  }
}

void FileBrowser::reset() {
  init_ = false;
}

void FileBrowser::setMenuSortIconMenu() {
  sort->addAction(nameSort);
  sort->removeAction(sizeSort);
  sort->removeAction(typeSort);
  sort->removeAction(dateSort);
  menu2->addAction(newFolder);
}

void FileBrowser::setMenuSortDetailMenu() {
  sort->addAction(nameSort);
  sort->addAction(sizeSort);
  sort->addAction(typeSort);
  sort->addAction(dateSort);
  menu2->addAction(newFolder);
}

void FileBrowser::setMenuSortNoFolderMenu() {
  menu2->removeAction(newFolder);
}

void FileBrowser::setMenuDirMenu() {
  menu->addAction(openFile);
  menu->removeAction(openWith);
  menu->addAction(saveFile);
  menu->addSeparator();
//  menu->addAction(cutFile);
//  menu->addAction(copyFile);
//  menu->addSeparator();
  menu->addAction(deleteFile);
  menu->addAction(renameFile);
  menu->addAction(sendFile);
}

void FileBrowser::setMenuFileMenu() {
  menu->addAction(openFile);
  menu->addAction(openWith);
  menu->addAction(saveFile);
  menu->addSeparator();
//  menu->addAction(cutFile);
//  menu->addAction(copyFile);
//  menu->addSeparator();
  menu->addAction(deleteFile);
  menu->addAction(renameFile);
  menu->addAction(sendFile);
}

void FileBrowser::setMenuReadOnlyMenu() {
  menu->removeAction(openFile);
  menu->removeAction(openWith);
  menu->removeAction(saveFile);
  menu->addSeparator();
//  menu->addAction(cutFile);
//  menu->addAction(copyFile);
//  menu->addSeparator();
  menu->removeAction(deleteFile);
  menu->removeAction(renameFile);
  menu->removeAction(sendFile);
}

void FileBrowser::dragEnterEvent(QDragEnterEvent *event) {
  qDebug() << "drag enter event";
  event->acceptProposedAction();
}

void FileBrowser::dropEvent(QDropEvent *event) {
  qDebug() << "drop event";
  QList<QUrl> urls = event->mimeData()->urls();
  QString fileName = urls.first().toLocalFile();
  qDebug() << fileName;
  uploadFileFromLocal(fileName);
}

void FileBrowser::onMousePressed(QTreeWidgetItem *item, int) {
  if (QApplication::mouseButtons() == Qt::RightButton) {
    if (item->text(3) == "Directory")
      setMenuDirMenu();
    else
      setMenuFileMenu();

    if (currentDir_.startsWith("/Emails/"))
      setMenuReadOnlyMenu();
    else if (currentDir_ == "/Shares/" || currentDir_ == "/Shares/Private/")
      setMenuReadOnlyMenu();

    menu->exec(QCursor::pos());
  }
}

void FileBrowser::onIconMousePressed(QListWidgetItem* item) {
  if (QApplication::mouseButtons() == Qt::RightButton) {
    if (item->toolTip().contains("Directory"))
      setMenuDirMenu();
    else
      setMenuFileMenu();

    if (currentDir_.startsWith("/Emails/"))
      setMenuReadOnlyMenu();
    else if (currentDir_ == "/Shares/" || currentDir_ == "/Shares/Private/")
      setMenuReadOnlyMenu();

    menu->exec(QCursor::pos());
  }
}

void FileBrowser::onOpenFileClicked() {
  if (viewMode_ == DETAIL) {
    QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
    onItemDoubleClicked(theItem, 0);
  } else {
    QListWidgetItem* theItem = ui_.driveListWidget->currentItem();
    onListItemDoubleClicked(theItem);
  }
}

void FileBrowser::onOpenWithClicked() {
  qDebug() << "Open With invoked";
  QString path;
  if (viewMode_ == DETAIL) {
    QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
    if (theItem->text(1) == tr("Network")) {
      QMessageBox::warning(this, tr("PD Error"),
                 tr("You must download the file before trying to open it"));
      return;
    }
    path = rootPath_ + currentDir_ + theItem->text(0);
  } else {
    QListWidgetItem* theItem = ui_.driveListWidget->currentItem();
    if (theItem->toolTip().contains(tr("Newtork"))) {
      QMessageBox::warning(this, tr("PD Error"),
          tr("You must download the file before trying to open it"));
      return;
  }
    path = rootPath_ + currentDir_ + theItem->text();
}

#if defined(PD_WIN32)
  QString operation("open");
  QString run = "RUNDLL32.EXE";
  QString parameters = "shell32.dll,OpenAs_RunDLL ";
  QString qtPath = getFullFilePath(path);
  quintptr returnValue;
  QT_WA({
    returnValue = (quintptr)ShellExecute(0,
                        (TCHAR *)(operation.utf16()),
                        (TCHAR *)(run.utf16()),
                        (TCHAR *)(parameters + qtPath).utf16(),
                        0,
                        SW_SHOWNORMAL);
      } , {
    returnValue = (quintptr)ShellExecuteA(0,
                        (TCHAR *)(operation.utf16()),
                        (TCHAR *)(run.utf16()),
                        (TCHAR *)(parameters + qtPath).utf16(),
                        0,
                        SW_SHOWNORMAL);
      });
      if (returnValue <= 32) {
        qWarning() << "FileBrowser::open: failed to open"
                   << path;
      }
#elif defined(PD_APPLE)
  QString fileName = QFileDialog::getOpenFileName(this,
                                      tr("Choose Application to open with"),
                                      "/Applications",
                                      tr("All Applications") +  "(*.app)");
  if (fileName.isEmpty()) {
    return;
  }


  qDebug() << "Asked to open with: " << fileName;

  QString command("open");
  QStringList parameters;
  parameters << "-a";
  parameters << fileName;
  parameters << QString::fromStdString(path.toStdString());
  myProcess_.reset(new QProcess);
  connect(myProcess_.get(), SIGNAL(error(QProcess::ProcessError)),
      this, SLOT(onOpenError(QProcess::ProcessError)));
  connect(myProcess_.get(), SIGNAL(started()),
      this, SLOT(onOpenStarted()));
  connect(myProcess_.get(), SIGNAL(finished(int, QProcess::ExitStatus)),
      this, SLOT(onOpenFinished(int, QProcess::ExitStatus)));
  // myProcess_->start(command, parameters);
  if (!myProcess_->startDetached("/usr/bin/open",
                                 QStringList() << parameters)) {
    qDebug() << ":'(";
  }
#else
// TODO(Team): Implement Open With for Linux
#endif
}

void FileBrowser::onSendFileClicked() {
  QString filename;
  if (viewMode_ == DETAIL) {
    QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
    filename = theItem->text(0);
  } else {
    QListWidgetItem* theItem = ui_.driveListWidget->currentItem();
    filename = theItem->text();
  }
  bool ok;
  QString text = QInputDialog::getText(this, tr("Who will receive the file?"),
                                       tr("Recipient"),
                                       QLineEdit::Normal, "", &ok);

  if (ok) {
    QList<QString> conts;
    conts.push_back(text);
    QString filePath = rootPath_ + currentDir_ + filename;

    if (ClientController::instance()->sendInstantFile(
        filePath, "", conts, "")) {
      QMessageBox::information(this, tr("File Sent"),
                               tr("Success sending file: %1").arg(filename));
    } else {
      const QString msg = tr("There was an error sending the file: %1")
                              .arg(filename);
      QMessageBox::warning(this, tr("File Not Sent"), msg);
    }
  }
}

void FileBrowser::onCopyFileClicked() {
}

void FileBrowser::onCutFileClicked() {
}

void FileBrowser::onDeleteFileClicked() {
  bool onNetwork;
  QString filename;
  if (viewMode_ == DETAIL) {
    QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
    onNetwork = (theItem->text(1) == tr("Network"));
    filename = theItem->text(0);
  } else {
    QListWidgetItem* theItem = ui_.driveListWidget->currentItem();
    onNetwork = theItem->toolTip().contains(tr("Network"));
    filename = theItem->text();
  }
  if (onNetwork) {
    QMessageBox msgBox;
    msgBox.setText(tr("Delete Item"));
    msgBox.setInformativeText(
        tr("Do you wish to remove %1?").arg(filename));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::Save);
    int ret = msgBox.exec();

    std::string str = currentDir_.toStdString() + filename.toStdString();
    std::string tidyRelPathStr = maidsafe::TidyPath(str);
    QString deletePath = QString::fromStdString(tidyRelPathStr);
    qDebug() << "create folder" << deletePath;

    if (ret == QMessageBox::Yes) {
      RemoveDirThread* rdt = new RemoveDirThread(deletePath,
                                                 this);

      connect(rdt,  SIGNAL(removeDirCompleted(int, const QString&)),
              this, SLOT(onRemoveDirCompleted(int, const QString&)));

      rdt->start();
    } else {
      return;
    }
  } else {
    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setText(tr("You can only delete networked files."));
    msgBox.exec();
  }
}

void FileBrowser::onNewFolderClicked() {
  bool ok;
    QString text = QInputDialog::getText(this, tr("Create Directory"),
        tr("Name of the new directory:"), QLineEdit::Normal,
        tr("New Folder", "default directory name"), &ok);
    if (ok && !text.isEmpty()) {
      std::string str = currentDir_.toStdString() + text.toStdString();
      std::string tidyRelPathStr = maidsafe::TidyPath(str);
      QString folderPath = QString::fromStdString(tidyRelPathStr);
      qDebug() << "create folder" << folderPath;

      MakeDirectoryThread* mdt = new MakeDirectoryThread(folderPath,
                                                          this);

      connect(mdt,  SIGNAL(makeDirectoryCompleted(int, const QString&)),
              this, SLOT(onMakeDirectoryCompleted(int, const QString&)));

      mdt->start();
    }
}

void FileBrowser::onRenameFileClicked() {
  bool ok;
  bool onNetwork;
  QString filename;
    if (viewMode_ == DETAIL) {
    QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
    onNetwork = (theItem->text(1) == tr("Network"));
    filename = theItem->text(0);
  } else {
    QListWidgetItem* theItem = ui_.driveListWidget->currentItem();
    onNetwork = theItem->toolTip().contains(tr("Network"));
    filename = theItem->text();
  }

  if (onNetwork) {
    QString text = QInputDialog::getText(this, tr("Rename File"),
        tr("New file name:"), QLineEdit::Normal, filename, &ok);
    if (ok && !text.isEmpty()) {
      std::string str = currentDir_.toStdString() + filename.toStdString();
      std::string tidyRelPathStr = maidsafe::TidyPath(str);
      QString oldFilePath = QString::fromStdString(tidyRelPathStr);
      qDebug() << "rename file from" << oldFilePath;

      std::string str1 = currentDir_.toStdString() + text.toStdString();
      std::string tidyRelPathStr1 = maidsafe::TidyPath(str1);
      QString newFilePath = QString::fromStdString(tidyRelPathStr1);
      qDebug() << "rename file from" << newFilePath;

      RenameFileThread* rft = new RenameFileThread(oldFilePath,
                                                   newFilePath, this);

      connect(rft,
              SIGNAL(renameFileCompleted(int, const QString&, const QString&)),
              this,
              SLOT(onRenameFileCompleted(int, const QString&, const QString&)));

      rft->start();
    }
  } else {
    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setText(tr("Renaming is only allowed for networked files."));
    msgBox.exec();
  }
}

void FileBrowser::onSaveFileClicked() {
  if (viewMode_ == DETAIL) {
    QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
    if (theItem->text(1) == tr("Local")) {
      theItem->setText(1, tr("Uploading"));
      saveFileToNetwork(currentDir_ + theItem->text(0));
    }
  } else {
    QListWidgetItem* theItem = ui_.driveListWidget->currentItem();
    if (theItem->toolTip().contains(tr("Local"))) {
      theItem->setToolTip(theItem->toolTip().replace(tr("Local"),
                              tr("Uploading"), Qt::CaseSensitive));
      saveFileToNetwork(currentDir_ + theItem->text());
    }
  }
}

void FileBrowser::onBackClicked(bool) {
  if (currentDir_ == "/" || currentDir_ == "") {
  } else {
    std::string dir = currentDir_.toStdString();
    dir.erase(dir.find_last_of("/"), dir.size());
    dir.erase(dir.find_last_of("/"), dir.size());
    populateDirectory(QString::fromStdString(dir) + "/");
  }
}

void FileBrowser::populateDirectory(QString dir) {
    currentDir_ = dir;
  switch (viewMode_) {
    case TILES:
      drawTileView();
      break;
    case DETAIL:
      drawDetailView();
      break;
    case LIST:
      drawIconView();
      break;
    case BIGLIST:
      drawIconView();
      break;
    case SMALLICONS:
      drawIconView();
      break;
    default:
      break;
  }
}

int FileBrowser::drawTileView() {
return 0;
}

int FileBrowser::drawDetailView() {
  ui_.driveTreeWidget->clear();
  ui_.locationEdit->setText(currentDir_);

  int rowCount = 0;
//  std::string relPathStr = currentDir_.toStdString();
  std::map<std::string, maidsafe::ItemType> children;
//  std::string tidyRelPathStr = maidsafe::TidyPath(relPathStr);
  ClientController::instance()->readdir(currentDir_, &children);

//  qDebug() << "populateDirectory: " << QString::fromStdString(tidyRelPathStr);

  QStringList columns;
  columns << tr("Name") << tr("Status") << tr("Size") << tr("Type")
          << tr("Date Modified");
  ui_.driveTreeWidget->setHeaderLabels(columns);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path(currentDir_.toStdString());
    path /= s;
    QString str(path.string().c_str());
    if (ClientController::instance()->getattr(str, &ser_mdm)) {
      qDebug() << "populateDirectory failed at getattr()";
      return -1;
    }

    mdm.ParseFromString(ser_mdm);

    QDateTime *lastModified = new QDateTime;
    QFileIconProvider *icon = new QFileIconProvider;
    int linuxtime = mdm.last_modified();
    lastModified->setTime_t(linuxtime);

    if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
      // Folder
      QString qtPath = getFullFilePath(rootPath_ + currentDir_
                                + QString::fromStdString(s));
      try {
        if (!fs::exists(qtPath.toStdString())) {
          fs::create_directory(qtPath.toStdString());
          qDebug() << "FileBrowser::drawDetailView - Create Directory :" <<
              QString::fromStdString(qtPath.toStdString());
        }
      }
      catch(const std::exception&) {
        qDebug() << "FileBrowser::drawDetailView - Create Directory Failed";
      }
      QIcon theIcon = icon->icon(QFileIconProvider::Folder);
      QString item = QString::fromStdString(s);
      QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.driveTreeWidget);
      newItem->setIcon(0, theIcon);
      newItem->setText(0, item);
      newItem->setText(1, tr("Network"));
      newItem->setText(2, tr("%1 KB")
                          .arg(ceil(static_cast<double>(mdm.file_size_low()) /
                                                        1024)));
      newItem->setText(3, tr("Directory"));
      // TODO(Team#): use date format from the user's locale
      newItem->setText(4, lastModified->toString("dd/MM/yyyy hh:mm"));

      ui_.driveTreeWidget->insertTopLevelItem(rowCount, newItem);
    } else {
      std::string fullFilePath = rootPath_.toStdString() +
                                currentDir_.toStdString() + s;
      QIcon theIcon = getAssociatedIconFromPath(
                      QString::fromStdString(fullFilePath));

      QString item = QString::fromStdString(s);
      QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.driveTreeWidget);
      newItem->setIcon(0, theIcon);
      newItem->setText(0, item);
      try {
        if (fs::exists(fullFilePath)) {
          newItem->setText(1, tr("Local"));
        } else {
          newItem->setText(1, tr("Network"));
        }
      }
      catch(const std::exception &e) {
#ifdef DEBUG
        printf("FileBrowser::drawDetailView - Can't analyse path.\n");
#endif
        continue;
      }
      newItem->setText(2, tr("%1 KB").arg(
          ceil(static_cast<double>(mdm.file_size_low())/1024)));
      newItem->setText(3, tr("%1 File").arg(item.section('.', -1)));
      // TODO(Team#): use date format from the user's locale
      newItem->setText(4, lastModified->toString("dd/MM/yyyy hh:mm"));
      ui_.driveTreeWidget->insertTopLevelItem(rowCount, newItem);
    }
    children.erase(children.begin());
    ++rowCount;
  }
  ui_.driveTreeWidget->resizeColumnToContents(1);
  ui_.driveTreeWidget->resizeColumnToContents(2);
  ui_.driveTreeWidget->resizeColumnToContents(3);
  return 0;
}
int FileBrowser::drawListView() {
return 0;
}

int FileBrowser::drawIconView() {
  ui_.driveListWidget->clear();
  ui_.locationEdit->setText(currentDir_);

  int rowCount = 0;
//  std::string relPathStr = currentDir_.toStdString();
  std::map<std::string, maidsafe::ItemType> children;
//  std::string tidyRelPathStr = maidsafe::TidyPath(relPathStr);
  ClientController::instance()->readdir(currentDir_, &children);

//  qDebug() << "drawIconView: " << QString::fromStdString(relPathStr);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path(currentDir_.toStdString());
    path /= s;
    QString str(path.string().c_str());
    if (ClientController::instance()->getattr(str, &ser_mdm)) {
      qDebug() << "drawIconView failed at getattr()";
      return -1;
    }

    mdm.ParseFromString(ser_mdm);

    QDateTime *lastModified = new QDateTime;
    QFileIconProvider *icon = new QFileIconProvider;
    int linuxtime = mdm.last_modified();
    lastModified->setTime_t(linuxtime);

    if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
      // Folder
      QString qtPath = getFullFilePath(rootPath_ + currentDir_
                                      + QString::fromStdString(s));
      if (!fs::exists(qtPath.toStdString())) {
        try {
          fs::create_directory(qtPath.toStdString());
          qDebug() << "Create Directory :" <<
              QString::fromStdString(qtPath.toStdString());
        }
        catch(const std::exception&) {
          qDebug() << "Create Directory Failed";
        }
      }
      QIcon theIcon = icon->icon(QFileIconProvider::Folder);
      QString item = QString::fromStdString(s);
      QListWidgetItem *newItem = new QListWidgetItem;
      newItem->setIcon(theIcon);
      newItem->setText(item);

      newItem->setToolTip(tr("Name: %1").arg(item) + "<br>" +
                          tr("Status: Network") +
                          "<br>" + tr("Type: Directory") + "<br>" +
                          tr("Size: %1 KB").arg(
                          ceil(static_cast<double>(mdm.file_size_low())/1024)) +
                          "<br>" + "Date Modified: " +
                          lastModified->toString("dd/MM/yyyy hh:mm"));
      ui_.driveListWidget->addItem(newItem);
    } else {
      std::string fullFilePath = rootPath_.toStdString() +
                                currentDir_.toStdString() + s;
      QIcon theIcon = getAssociatedIconFromPath(
                      QString::fromStdString(fullFilePath));

      QString item = QString::fromStdString(s);
      QListWidgetItem *newItem = new QListWidgetItem;
      newItem->setIcon(theIcon);
      newItem->setText(item);
      QString tip;
      tip = tr("Name: %1").arg(item) + "<br>";
      try {
        if (fs::exists(fullFilePath)) {
          tip.append(tr("Status: Local") + "<br>");
        } else {
          tip.append(tr("Status: Network") + "<br>");
        }
      }
      catch(const std::exception &e) {
#ifdef DEBUG
        printf("FileBrowser::drawIconView - Can't analyse path.\n");
#endif
        continue;
      }
      tip.append(tr("Type: %1 File").arg(item.section('.', -1)));
      tip.append("<br>");
      tip.append(tr("Size: %1 KB").arg(
          ceil(static_cast<double>(mdm.file_size_low())/1024)));
      tip.append("<br>");
      tip.append(tr("Date Modified: ") +
                      lastModified->toString("dd/MM/yyyy hh:mm"));
      newItem->setToolTip(tip);
//      ui_.driveListWidget->setItemDelegate(bigListDelegate_);
//      newItem->setData(0, qVariantFromValue(QString(tip)));
      ui_.driveListWidget->addItem(newItem);
    }
    children.erase(children.begin());
    ++rowCount;
  }
  if (viewMode_ == LIST || viewMode_ == BIGLIST) {
    ui_.driveListWidget->setViewMode(QListView::ListMode);
    ui_.driveListWidget->setFlow(QListView::TopToBottom);
    ui_.driveListWidget->setUniformItemSizes(false);
    ui_.driveListWidget->setGridSize(QSize());
    ui_.driveTreeWidget->setWordWrap(true);
    if (viewMode_ == BIGLIST)
      ui_.driveListWidget->setIconSize(QSize(32, 32));
    else
      ui_.driveListWidget->setIconSize(QSize());
  } else {
    ui_.driveListWidget->setViewMode(QListView::IconMode);
    ui_.driveListWidget->setFlow(QListView::LeftToRight);
    ui_.driveListWidget->setWordWrap(false);
    ui_.driveListWidget->setGridSize(QSize(90, 80));
  }
  return 0;
}

int FileBrowser::createTreeDirectory(QString) {
  qDebug() << "createTreeDirectory: ";
  ui_.treeViewTreeWidget->clear();
  currentTreeDir_ = "/";
  int rowCount = 0;
//  std::string relPathStr = currentTreeDir_.toStdString() + dir.toStdString();
  std::map<std::string, maidsafe::ItemType> children;
//  std::string tidyRelPathStr = maidsafe::TidyPath(relPathStr);
  ClientController::instance()->readdir(currentTreeDir_, &children);

  qDebug() << "createTreeDirectory: ";
  QStringList columns;
  columns << tr("Folder");
  ui_.treeViewTreeWidget->setHeaderLabels(columns);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path(currentTreeDir_.toStdString());
    path /= s;
    QString str(path.string().c_str());
    if (ClientController::instance()->getattr(str, &ser_mdm)) {
      qDebug() << "populateDirectory failed at getattr()";
      return -1;
    }
    mdm.ParseFromString(ser_mdm);

    QFileIconProvider *icon = new QFileIconProvider;

    if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
      QIcon theIcon = icon->icon(QFileIconProvider::Folder);
      QString item = QString::fromStdString(s);
      QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.treeViewTreeWidget);
      newItem->setIcon(0, theIcon);
      newItem->setText(0, item);

      std::string relPathStr1 = currentTreeDir_.toStdString() + s + "/";
      std::map<std::string, maidsafe::ItemType> children1;
      ClientController::instance()->readdir(QString::fromStdString(relPathStr1),
                                            &children1);

      if (!children1.empty()) {
        QTreeWidgetItem *emptyItem = new QTreeWidgetItem(newItem);
        emptyItem->setText(0, "fake");
      }

      ui_.driveTreeWidget->insertTopLevelItem(rowCount, newItem);
    }
    children.erase(children.begin());
    rowCount++;
  }
  return 0;
}

void FileBrowser::onListItemDoubleClicked(QListWidgetItem* item) {
  if (item->toolTip().contains("Directory")) {
    populateDirectory(currentDir_ + item->text() + "/");
  } else {
    if (item->toolTip().contains("Network")) {
      item->setToolTip(item->toolTip().replace("Network",
                      "Downloading", Qt::CaseSensitive));

      std::string tidyRelPathStr = maidsafe::TidyPath(currentDir_.toStdString()
                                                 + item->text().toStdString());
      QString openFilePath = QString::fromStdString(tidyRelPathStr);
      qDebug() << "upload File" << openFilePath;

      ReadFileThread* rft = new ReadFileThread(openFilePath,
                                               this);

      connect(rft,  SIGNAL(readFileCompleted(int, const QString&)),
              this, SLOT(onReadFileCompleted(int, const QString&)));

      rft->start();

    } else if (item->toolTip().contains("Local")) {
      QString path = rootPath_ + currentDir_ + item->text();
      openFileFromDir(path);
    }
  }
}

void FileBrowser::onItemDoubleClicked(QTreeWidgetItem* item, int) {
  if (item->text(3) == "Directory") {
    populateDirectory(currentDir_  + item->text(0) + "/");
  } else {
    if (item->text(1) == tr("Network")) {
      ui_.driveTreeWidget->editItem(item, 1);
      item->setText(1, tr("Downloading"));

      std::string tidyRelPathStr = maidsafe::TidyPath(currentDir_.toStdString()
                                                + item->text(0).toStdString());
      QString openFilePath = QString::fromStdString(tidyRelPathStr);
      qDebug() << "upload File" << openFilePath;

      ReadFileThread* rft = new ReadFileThread(openFilePath,
                                               this);

      connect(rft,  SIGNAL(readFileCompleted(int, const QString&)),
              this, SLOT(onReadFileCompleted(int, const QString&)));

      rft->start();
    } else if (item->text(1) == tr("Downloading") ||
               item->text(1) == tr("Uploading")) {
      QMessageBox msgBox;
      msgBox.setIcon(QMessageBox::Warning);
      msgBox.setText(tr("Please wait for the file transfer to finish."));
      msgBox.exec();
    } else {
      QString path = rootPath_ + currentDir_ + item->text(0);
      openFileFromDir(path);
    }
  }
}

void FileBrowser::openFileFromDir(const QString path) {
#if defined(PD_WIN32)
      QString operation("open");
      quintptr returnValue;
      QT_WA({
        returnValue = (quintptr)ShellExecute(0,
                          (TCHAR *)(operation.utf16()),
                          (TCHAR *)(path.utf16()),
                          0,
                          0,
                          SW_SHOWNORMAL);
      } , {
        returnValue = (quintptr)ShellExecuteA(0,
                                  operation.toLocal8Bit().constData(),
                                  path.toLocal8Bit().constData(),
                                  0,
                                  0,
                                  SW_SHOWNORMAL);
      });
      if (returnValue <= 32) {
        qWarning() << "FileBrowser::open: failed to open"
                   << path;
      }
#elif defined(PD_POSIX)
      QString command;
      QStringList parameters;
      try {
        if (!boost::filesystem::exists("/usr/bin/gnome-open")) {
          if (!boost::filesystem::exists("/usr/bin/kde-open")) {
          } else {
            command = tr("/usr/bin/kde-open");
          }
        } else {
          command = tr("/usr/bin/gnome-open");
        }
      }
      catch(const std::exception &e) {
        qDebug() << "FileBrowser::openFileFromDir - "
                 << "Couldn't find executing command";
      }
      if (!command.isEmpty()) {
        parameters << QString::fromStdString(path.toStdString());
        myProcess_.reset(new QProcess);
        myProcess_->start(command, parameters);
      }
#elif defined(PD_APPLE)
      QString command("open");
      QStringList parameters;
      parameters << QString::fromStdString(path.toStdString());
      myProcess_.reset(new QProcess);
      connect(myProcess_.get(), SIGNAL(error(QProcess::ProcessError)),
              this,             SLOT(onOpenError(QProcess::ProcessError)));
      connect(myProcess_.get(), SIGNAL(started()),
              this,             SLOT(onOpenStarted()));
      connect(myProcess_.get(),
                  SIGNAL(finished(int, QProcess::ExitStatus)),
              this,
                  SLOT(onOpenFinished(int, QProcess::ExitStatus)));
      // myProcess_->start(command, parameters);
      if (!myProcess_->startDetached("/usr/bin/open",
          QStringList() << parameters)) {
        qDebug() << ":'(";
      }
#endif
}

void FileBrowser::onOpenError(QProcess::ProcessError e) {
  qDebug() << "OpenError: " << e;
}

void FileBrowser::onOpenStarted() {
  qDebug() << "OpenStarted";
}

void FileBrowser::onOpenFinished(int exitCode,
                                 QProcess::ExitStatus exitStatus) {
  qDebug() << "OpenFinished: " << exitCode << ", " << exitStatus;
}

void FileBrowser::onReadFileCompleted(int success, const QString& filepath) {
  if (success != -1) {
    std::string dir = filepath.toStdString();
    dir.erase(0, 1);
//    theWatcher_->addPath(rootPath_ + QString::fromStdString(dir));

    std::string file = filepath.toStdString();
    file.erase(0, file.find_last_of("/") + 1);
    QString theFile = QString::fromStdString(file);

    if (viewMode_ == DETAIL) {
      QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
                                                theFile, Qt::MatchExactly, 0);
      if (!widgetList.empty()) {
        QTreeWidgetItem* theWidget = widgetList[0];
        ui_.driveTreeWidget->editItem(theWidget, 1);
        theWidget->setText(1, tr("Local"));
      }
    } else {
      QList<QListWidgetItem *> widgetList = ui_.driveListWidget->findItems(
                                                theFile, Qt::MatchExactly);
      if (!widgetList.empty()) {
        QListWidgetItem* theWidget = widgetList[0];
        theWidget->setToolTip(theWidget->toolTip().replace("Downloading",
                                            "Local", Qt::CaseSensitive));
      }
    }
  }
}

//  void FileBrowser::onWatchedFileChanged(const QString& path) {
//    qDebug() << "onWatchedFileChanged : " << path;
//    std::string file = path.toStdString();
//    file.erase(0,file.find_last_of("/")+1);
//    QString theFile = QString::fromStdString(file);
//
//    QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
//                                              theFile, Qt::MatchExactly, 0);
//
//    qDebug() << "in onWatchedFileChanged : File to modify" << theFile;
//
//    if (!widgetList.empty())
//    {
//      QTreeWidgetItem* theWidget = widgetList[0];
//      ui_.driveTreeWidget->editItem(theWidget, 1);
//      //theWidget->setText(1, "Edited");
//    } else {
//      qDebug() << "onWatchFileChanged : no file matched" << theFile;
//    }
//  }

void FileBrowser::onSaveFileCompleted(int success, const QString& filepath) {
  qDebug() << "onSaveFileCompleted : " << filepath;
  if (success != -1) {
    std::string dir = filepath.toStdString();
    dir.erase(0, 1);
//    theWatcher_->removePath(rootPath_ + QString::fromStdString(dir));

    std::string fullFilePath(rootPath_.toStdString() + filepath.toStdString());

    try {
      if (fs::exists(fullFilePath)) {
        fs::remove(fullFilePath);
        qDebug() << "Remove File Success:"
                 << QString::fromStdString(fullFilePath);
      }
    }
    catch(const std::exception&) {
        qDebug() << "Remove File failure:"
                 << QString::fromStdString(fullFilePath);
    }

    std::string file(filepath.toStdString());
    file.erase(0, file.find_last_of("/") + 1);
    QString theFile(QString::fromStdString(file));

    if (viewMode_ == DETAIL) {
      QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
                                              theFile, Qt::MatchExactly, 0);

      if (!widgetList.empty()) {
        QTreeWidgetItem* theWidget = widgetList[0];
        ui_.driveTreeWidget->editItem(theWidget, 1);
        theWidget->setText(1, tr("Network"));
      }
    } else {
      QList<QListWidgetItem *> widgetList = ui_.driveListWidget->findItems(
                                                theFile, Qt::MatchExactly);
      if (!widgetList.empty()) {
        QListWidgetItem* theWidget = widgetList[0];
        theWidget->setToolTip(theWidget->toolTip().replace(tr("Uploading"),
                                        tr("Network"), Qt::CaseSensitive));
      }
    }
    populateDirectory(currentDir_);
  } else {
    qDebug() << "onSaveFileCompleted : no file found";
  }
}

void FileBrowser::uploadFileFromLocal(const QString& filePath) {
  std::string filename = filePath.toStdString();
  filename.erase(0, filename.find_last_of("/") + 1);
  qDebug() << "Upload File From Local: "
           << QString::fromStdString(filename);

  std::string fullFilePath(rootPath_.toStdString() + currentDir_.toStdString()
                           + filename);

  std::string tidyRelPathStr = maidsafe::TidyPath(currentDir_.toStdString() +
                                                                    filename);
  QString uploadFilePath = QString::fromStdString(tidyRelPathStr);
  qDebug() << "upload File" << uploadFilePath;

  QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
                                            QString::fromStdString(filename),
                                            Qt::MatchExactly, 0);

  if (widgetList.isEmpty()) {
    try {
      fs::copy_file(filePath.toStdString(), fullFilePath);
      if (fs::exists(fullFilePath)) {
        saveFileToNetwork(uploadFilePath);
      } else {
        qDebug() << "CopyFile Failed";
      }
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("FileBrowser::uploadFileFromLocal - Failed to copy file\n");
#endif
    }
  } else {
    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setText(tr("A file with the same name already exists! Please rename "
                      "your file before uploading."));
    msgBox.exec();
  }
}

void FileBrowser::saveFileToNetwork(const QString& filePath) {
//  start save thread
  SaveFileThread* sft = new SaveFileThread(filePath, this);
  connect(sft,  SIGNAL(saveFileCompleted(int, const QString&)),
          this, SLOT(onSaveFileCompleted(int, const QString&)));
  sft->start();
}

void FileBrowser::onUploadClicked(bool b) {
  if (b) {
  }
  QStringList fileNames = QFileDialog::getOpenFileNames(this,
                                                        tr("Upload a File"),
                                                        "",
                                                        tr("Any file") + "(*)");
  if (fileNames.isEmpty()) {
    return;
  }
  const QString filename = fileNames.at(0);
  qDebug() << filename;
  uploadFileFromLocal(filename);
}

void FileBrowser::onRenameFileCompleted(int success, const QString& filepath,
                                        const QString& newfilepath) {
  qDebug() << "in onRenameFileCompleted:" + newfilepath;
  if (success != -1) {
    std::string fullFilePath = rootPath_.toStdString() +
                        currentDir_.toStdString() + filepath.toStdString();
    std::string fullNewFilePath = rootPath_.toStdString() +
                        currentDir_.toStdString() + newfilepath.toStdString();

    qDebug() << "Rename Success";
    populateDirectory(currentDir_);
  }
}

void FileBrowser::onMakeDirectoryCompleted(int success, const QString& dir) {
  qDebug() << "in onMakeDirectoryCompleted:" + dir;
  if (success != -1) {
    qDebug() << "MakeDir Success";
    populateDirectory(currentDir_);
    createTreeDirectory("/");
  }
}

void FileBrowser::onRemoveDirCompleted(int success, const QString& path) {
  qDebug() << "in onRemoveDirCompleted:" + path;
  if (success != -1) {
    qDebug() << "RemoveDir Success";
    populateDirectory(currentDir_);
  }
}

bool FileBrowser::eventFilter(QObject *obj, QEvent *event) {
  if (obj == ui_.driveTreeWidget->viewport() || obj == ui_.driveListWidget) {
    if (event->type() == QEvent::ContextMenu) {
      if (obj == ui_.driveTreeWidget->viewport())
        setMenuSortDetailMenu();
      else
        setMenuSortIconMenu();
    if (currentDir_.startsWith("/Emails/"))
      setMenuSortNoFolderMenu();
    else if (currentDir_ == "/Shares/" || currentDir_ == "/Shares/Private/")
      setMenuSortNoFolderMenu();

      menu2->exec(QCursor::pos());
      return true;
    } else {
      return false;
    }
  } else {
    // pass the event on to the parent class
    return FileBrowser::eventFilter(obj, event);
  }
}

void FileBrowser::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

void FileBrowser::onItemExpanded(QTreeWidgetItem* item) {
  qDebug() << "Item Expanded: ";
  while (item->childCount() > 0) {
    item->removeChild(ui_.treeViewTreeWidget->itemBelow(item));
  }

  currentTreeDir_ = getCurrentTreePath(item);

  int rowCount = 0;
  QString folder = item->text(0);
  std::string relPathStr(currentTreeDir_.toStdString() +
                         folder.toStdString() + "/");
  currentTreeDir_ = QString::fromStdString(relPathStr);
  std::map<std::string, maidsafe::ItemType> children;
  ClientController::instance()->readdir(currentTreeDir_, &children);
//  qDebug() << "Path String : " << QString::fromStdString(relPathStr);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path(relPathStr);
    path /= s;
    QString str(path.string().c_str());
    if (ClientController::instance()->getattr(str, &ser_mdm)) {
      qDebug() << "onItemExpanded failed at getattr()";
    }
    mdm.ParseFromString(ser_mdm);
    QFileIconProvider *icon = new QFileIconProvider;

    if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
      QIcon theIcon = icon->icon(QFileIconProvider::Folder);
      QString theItem = QString::fromStdString(s);
      QTreeWidgetItem *newItem = new QTreeWidgetItem(item);
      newItem->setIcon(0, theIcon);
      newItem->setText(0, theItem);

      std::string relPathStr1 = relPathStr + s + "/";
      std::map<std::string, maidsafe::ItemType> children1;
      ClientController::instance()->readdir(QString::fromStdString(relPathStr1),
                                            &children1);
      while (!children1.empty()) {
       maidsafe::ItemType ityp = children.begin()->second;
       if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
         QTreeWidgetItem *emptyItem = new QTreeWidgetItem(newItem);
         break;
       }
       children1.erase(children1.begin());
      }
      ui_.driveTreeWidget->insertTopLevelItem(rowCount, newItem);
    }
    children.erase(children.begin());
    ++rowCount;
  }
}

void FileBrowser::onFolderItemPressed(QTreeWidgetItem* item, int) {
  if (QApplication::mouseButtons() == Qt::LeftButton) {
    QString dir = getCurrentTreePath(item);
    populateDirectory(dir + item->text(0) + "/");
  }
}

void FileBrowser::setViewMode(ViewMode viewMode) {
  viewMode_ = viewMode;
  switch (viewMode) {
    case TILES:
      ui_.driveTreeWidget->setVisible(false);
      ui_.driveListWidget->setVisible(true);
      break;
    case DETAIL:
      ui_.driveTreeWidget->setVisible(true);
      ui_.driveListWidget->setVisible(false);
      break;
    case LIST:
      ui_.driveTreeWidget->setVisible(false);
      ui_.driveListWidget->setVisible(true);
      break;
    case BIGLIST:
      ui_.driveTreeWidget->setVisible(false);
      ui_.driveListWidget->setVisible(true);
      break;
    case SMALLICONS:
      ui_.driveTreeWidget->setVisible(false);
      ui_.driveListWidget->setVisible(true);
      break;
    default:
      break;
  }
  populateDirectory(currentDir_);
}

void FileBrowser::onViewGroupClicked(QAction* action) {
  if (action == tilesMode)
    setViewMode(TILES);
  else if (action == listMode)
    setViewMode(LIST);
  else if (action == detailMode)
    setViewMode(DETAIL);
  else if (action == iconMode)
    setViewMode(SMALLICONS);
  else if (action == bigListMode)
    setViewMode(BIGLIST);
}
void FileBrowser::onSortGroupClicked(QAction* action) {
  QHeaderView* theHeader = ui_.driveTreeWidget->header();
  Qt::SortOrder order = theHeader->sortIndicatorOrder();

  if (order == Qt::AscendingOrder)
    order = Qt::DescendingOrder;
  else
    order = Qt::AscendingOrder;

  if (action == nameSort) {
    ui_.driveTreeWidget->sortByColumn(0, order);
  } else if (action == sizeSort) {
    ui_.driveTreeWidget->sortByColumn(2, order);
  } else if (action == typeSort) {
    ui_.driveTreeWidget->sortByColumn(3, order);
  } else if (action == dateSort) {
    ui_.driveTreeWidget->sortByColumn(4, order);
  }
  ui_.driveListWidget->sortItems(order);
}

QString FileBrowser::getCurrentTreePath(QTreeWidgetItem* item) {
  QString path = "/";
  QTreeWidgetItem* item1 = new QTreeWidgetItem();
  item1 = item->parent();
  if (item1 != NULL) {
    while (item1->text(0) != "") {
    qDebug() << "Parent = " << item1->text(0);
    path = "/" + item1->text(0) + path;
    QTreeWidgetItem* item2 = new QTreeWidgetItem();
    item2 = item1->parent();
    if (item2 == NULL)
      break;
    item1 = item2;
    }
  }
  return path;
}

QIcon FileBrowser::getAssociatedIconFromPath(const QString& fullFilePath) {
  QString qtPath = getFullFilePath(fullFilePath);
  try {
    if (fs::exists(qtPath.toStdString())) {
      QFileInfo fileInfo(qtPath);
      QFileIconProvider fileIconProvider;
      QIcon appIcon = fileIconProvider.icon(fileInfo);
      return appIcon;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FileBrowser::getAssociatedIconFromPath - Failed to asses path\n");
#endif
  }

  if (!fs::exists(qtPath.toStdString())) {
    try {
      std::ofstream myfile;
      myfile.open(qtPath.toStdString().c_str());
      myfile << "Writing this to a dummy file.\n";
      myfile.close();
    }
    catch(const std::exception&) {
      qDebug() << "Create File Failed";
    }
  }

  QFileInfo fileInfo(qtPath);
  QFileIconProvider fileIconProvider;
  QIcon appIcon = fileIconProvider.icon(fileInfo);

  if (fs::exists(qtPath.toStdString())) {
    try {
      fs::remove(qtPath.toStdString());
    }
    catch(const std::exception&) {
      qDebug() << "Create File Failed";
    }
  }
  return appIcon;
}

QString FileBrowser::getFullFilePath(const QString& filepath) {
  QString qtPath = filepath;
  qtPath.replace(QString("//"), QString("/"));
  //qtPath.replace(QString("/"), QString("//"));
  return qtPath;
}

