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

#include "fs/filesystem.h"
#include "qt/client/user_space_filesystem.h"
#include <math.h>
#ifdef MAIDSAFE_WIN32
#include <windows.h>
#include <shellapi.h>
#endif

#include <QDebug>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QMouseEvent>
#include <QUrl>

#include "maidsafe/client/clientcontroller.h"
#include "qt/client/client_controller.h"
#include "qt/client/make_directory_thread.h"
#include "qt/client/read_file_thread.h"
#include "qt/client/remove_dir_thread.h"
#include "qt/client/rename_file_thread.h"
#include "qt/client/save_file_thread.h"

namespace fs = boost::filesystem;

 FileBrowser::FileBrowser(QWidget* parent) : init_(false) {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/16/globe"));
  //theWatcher_ = new QFileSystemWatcher;
  ui_.driveTreeWidget->setAcceptDrops(true);
  ui_.driveTreeWidget->viewport()->installEventFilter(this);

  menu = new QMenu(this);

  openFile = new QAction(tr("Open"), this);
  sendFile = new QAction(tr("Send"), this);
  cutFile = new QAction(tr("Cut"), this);
  copyFile = new QAction(tr("Copy"), this);
  deleteFile = new QAction(tr("Delete"), this);
  renameFile = new QAction(tr("Rename"), this);
  saveFile = new QAction(tr("Save"), this);

  menu->addAction(openFile);
  menu->addAction(saveFile);
  menu->addSeparator();
  //menu->addAction(cutFile);
  //menu->addAction(copyFile);
  //menu->addSeparator();
  menu->addAction(deleteFile);
  menu->addAction(renameFile);
  menu->addAction(sendFile);

  menu2 = new QMenu(this);
  newFolder = new QAction(tr("New Folder"), this);
  menu2->addAction(newFolder);

  connect(ui_.driveTreeWidget, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int)),
          this,            SLOT(onItemDoubleClicked(QTreeWidgetItem*, int)));

  connect(ui_.driveTreeWidget, SIGNAL(itemPressed(QTreeWidgetItem*, int)),
          this,            SLOT(onMousePressed(QTreeWidgetItem*, int)));

  //connect(theWatcher_, SIGNAL(fileChanged(const QString&)),
     //     this,        SLOT(onWatchedFileChanged(const QString&)));

  connect(ui_.backButton, SIGNAL(clicked(bool)),
          this,           SLOT(onBackClicked(bool)));

  connect(ui_.uploadButton, SIGNAL(clicked(bool)),
          this,           SLOT(onUploadClicked(bool)));

  connect(openFile, SIGNAL(triggered()),
          this,        SLOT(onOpenFileClicked()));

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

  connect(newFolder, SIGNAL(triggered()),
          this,        SLOT(onNewFolderClicked()));
}

FileBrowser::~FileBrowser() {
  reset();
}

void FileBrowser::setActive(bool b) {
  if (b && !init_) {
    init_ = true;

    rootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                    ClientController::instance()->SessionName()).string()+"/");

    qDebug() << rootPath_;

    populateDirectory("/");
    ui_.driveTreeWidget->header()->setResizeMode(QHeaderView::Interactive);
    ui_.driveTreeWidget->header()->setStretchLastSection(true);
  }
}

void FileBrowser::reset() {
  init_ = false;
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

void FileBrowser::onMousePressed(QTreeWidgetItem* item, int column) {
  if(QApplication::mouseButtons() == Qt::RightButton){
    menu->exec(QCursor::pos());
  }
}

void FileBrowser::onOpenFileClicked() {
  QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();

  onItemDoubleClicked(theItem, 0);
}

void FileBrowser::onSendFileClicked() {
  QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
  QString filename = theItem->text(0);
  bool ok;
  QString text = QInputDialog::getText(this, tr("Who will receive the file?"),
                                       tr("Recipient"),
                                       QLineEdit::Normal,"", &ok);

  if (ok){
    QList<QString> conts;
    conts.push_back(text);
    QString filePath = rootPath_ + currentDir_ + filename;

    if (ClientController::instance()->sendInstantFile(filePath, "", conts,""))
    {
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
  QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
  qDebug() << theItem->text(0);
  if(theItem->text(1) == tr("Network")) {
    QMessageBox msgBox;
    msgBox.setText(tr("Delete Item"));
    msgBox.setInformativeText(
        tr("Do you wish to remove %1?").arg(theItem->text(0)));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::Save);
    int ret = msgBox.exec();
    if (ret == QMessageBox::Yes) {
      RemoveDirThread* rdt = new RemoveDirThread(currentDir_ + theItem->text(0),
                                                          this);

      connect(rdt, SIGNAL(removeDirCompleted(int,const QString&)),
          this, SLOT(onRemoveDirCompleted(int,const QString&)));

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
    if (ok && !text.isEmpty()){
      MakeDirectoryThread* mdt = new MakeDirectoryThread(currentDir_ + text,
                                                          this);

      connect(mdt, SIGNAL(makeDirectoryCompleted(int,const QString&)),
          this, SLOT(onMakeDirectoryCompleted(int,const QString&)));

      mdt->start();
    }
}

void FileBrowser::onRenameFileClicked() {
  bool ok;
  QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
  qDebug() << theItem->text(1);
  if(theItem->text(1) == tr("Network")){

    QString text = QInputDialog::getText(this, tr("Rename File"),
        tr("New file name:"), QLineEdit::Normal, theItem->text(0), &ok);
    if (ok && !text.isEmpty()){
      RenameFileThread* rft = new RenameFileThread(currentDir_ +
          theItem->text(0), currentDir_ + text ,this);

      connect(rft,
              SIGNAL(renameFileCompleted(int,const QString&, const QString&)),
              this,
              SLOT(onRenameFileCompleted(int,const QString&, const QString&)));

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
  QTreeWidgetItem* theItem = ui_.driveTreeWidget->currentItem();
  if (theItem->text(1) == tr("Local")) {
    //ui_.driveTreeWidget->editItem(item, 1);
    theItem->setText(1, tr("Uploading"));
    saveFileToNetwork(currentDir_ + theItem->text(0));
  }
}

void FileBrowser::onBackClicked(bool) {
  if(currentDir_ == "/" || currentDir_ == "") {
  } else {
  std::string dir = currentDir_.toStdString();
  dir.erase(dir.find_last_of("/"), dir.size());
  dir.erase(dir.find_last_of("/"), dir.size());
  populateDirectory(QString::fromStdString(dir) + "/");
  }
}

int FileBrowser::populateDirectory(QString dir) {
  qDebug() << "populateDirectory: " << dir;
  ui_.driveTreeWidget->clear();
  currentDir_ = dir;

  int rowCount = 0;
  std::string relPathStr = dir.toStdString();
  std::map<std::string, maidsafe::ItemType> children;
  ClientController::instance()->readdir(relPathStr, children);

  qDebug() << "populateDirectory: " << QString::fromStdString(relPathStr);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path_(relPathStr);
    path_ /= s;
    if (ClientController::instance()->getattr(path_.string(), ser_mdm)) {
      qDebug() << "populateDirectory failed at getattr()";
      return -1;
    }

    QStringList columns;
    columns << "Name" << "Status" << "Size" << "Type" << "Date Modified" ;
    ui_.driveTreeWidget->setHeaderLabels(columns);
    ui_.driveTreeWidget->resizeColumnToContents(2);
    ui_.driveTreeWidget->resizeColumnToContents(3);

    mdm.ParseFromString(ser_mdm);
    const char *charpath(s.c_str());

    QDateTime *lastModified = new QDateTime;
    QFileIconProvider *icon = new QFileIconProvider;
    int linuxtime = mdm.last_modified();
    lastModified->setTime_t(linuxtime);

    if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
      //Folder
      std::string branchPath = rootPath_.toStdString()
                            + currentDir_.toStdString() + s;
      if (!fs::exists(branchPath)) {
        try {
          fs::create_directory(branchPath);
          qDebug() << "Create Directory :" <<
              QString::fromStdString(branchPath);
        }
        catch(const std::exception&) {
          qDebug() << "Create Directory Failed";
        }
      }

      QIcon theIcon = icon->icon(QFileIconProvider::Folder);

      QString item = QString::fromStdString(s);
      QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.driveTreeWidget);
      newItem->setIcon(0, theIcon);
      newItem->setText(0, item);
      newItem->setText(1, tr("Network"));
      newItem->setText(2, tr("%1 KB").arg(
          ceil(static_cast<double>(mdm.file_size_low())/1024)));
      // TODO(Team#) use date format from the user's locale
      newItem->setText(4, lastModified->toString("dd/MM/yyyy hh:mm"));
      ui_.driveTreeWidget->insertTopLevelItem(rowCount, newItem);

    } else {
       //File
      QIcon theIcon = icon->icon(QFileIconProvider::File);

      QString item = QString::fromStdString(s);
      QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.driveTreeWidget);
      newItem->setIcon(0, theIcon);
      newItem->setText(0, item);
      std::string fullFilePath = rootPath_.toStdString() +
                                currentDir_.toStdString() + s;
      if (fs::exists(fullFilePath)) {
        newItem->setText(1, tr("Local"));
      } else {
        newItem->setText(1, tr("Network"));
      }
      newItem->setText(2, tr("%1 KB").arg(
          ceil(static_cast<double>(mdm.file_size_low())/1024)));
      newItem->setText(3, tr("%1 File").arg(item.section('.', -1)));
      // TODO(Team#) use date format from the user's locale
      newItem->setText(4, lastModified->toString("dd/MM/yyyy hh:mm"));
      ui_.driveTreeWidget->insertTopLevelItem(rowCount, newItem);
    }
    children.erase(children.begin());
    rowCount++;
  }
  return 0;
}

void FileBrowser::onItemDoubleClicked(QTreeWidgetItem* item, int column) {
  qDebug() << "Entered ItemDoubleClicked";
  if (item->text(3) == ""){
    qDebug() << "in ItemDoubleClicked open folder" << "/" << item->text(0) <<
        "/";
    populateDirectory(currentDir_  + item->text(0) + "/");
  } else {
    if (item->text(1) == tr("Network")) {
      ui_.driveTreeWidget->editItem(item, 1);
      item->setText(1, tr("Downloading"));

      ReadFileThread* rft = new ReadFileThread(currentDir_ + item->text(0),
                                               this);

      connect(rft, SIGNAL(readFileCompleted(int,const QString&)),
          this, SLOT(onReadFileCompleted(int,const QString&)));

      rft->start();
    } else if (item->text(1) == tr("Downloading") ||
               item->text(1) == tr("Uploading")) {
      QMessageBox msgBox;
      msgBox.setIcon(QMessageBox::Warning);
      msgBox.setText(tr("Please wait for the file transfer to finish."));
      msgBox.exec();
    } else {
      QString path = rootPath_ + currentDir_ + item->text(0);

      qDebug() << "Item Double Clicked open file: " + path;
#if defined(MAIDSAFE_WIN32)
      QString operation("open");
      quintptr returnValue;
      QT_WA({
        returnValue = (quintptr)ShellExecute(0,
                          (TCHAR *)(operation.utf16()),
                          (TCHAR *)(path.utf16()),
                          0,
                          0,
                          SW_SHOWNORMAL);
//////////////////////////
//Open With Code Below //
////////////////////////
      /*QString run = "RUNDLL32.EXE";
      QString parameters = "shell32.dll,OpenAs_RunDLL ";
      returnValue = (quintptr)ShellExecute(0,
                          (TCHAR *)(operation.utf16()),
                          (TCHAR *)(run.utf16()),
                          (TCHAR *)(parameters + path).utf16(),
                          0,
                          SW_SHOWNORMAL);*/
//////////////
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
#elif defined(MAIDSAFE_POSIX)
      QString command;
      QStringList parameters;
      if (!boost::filesystem::exists("/usr/bin/gnome-open")) {
        if (!boost::filesystem::exists("/usr/bin/kde-open")) {
        } else {
          command = tr("/usr/bin/kde-open");
        }
      } else {
        command = tr("/usr/bin/gnome-open");
      }
      if (!command.isEmpty()) {
        parameters << QString::fromStdString(path.toStdString());
        myProcess_.reset(new QProcess);
        myProcess_->start(command, parameters);
      }
#elif defined(MAIDSAFE_APPLE)
      QString command("open");
      QStringList parameters;
      parameters << QString::fromStdString(path.toStdString());
      myProcess_.reset(new QProcess);
      myProcess_->start(command, parameters);
#endif
    }
  }
}

void FileBrowser::onReadFileCompleted(int success, const QString& filepath) {
  if (success != -1){
    std::string dir = filepath.toStdString();
    dir.erase(0,1);
//    theWatcher_->addPath(rootPath_ + QString::fromStdString(dir));

    std::string file = filepath.toStdString();
    file.erase(0,file.find_last_of("/")+1);
    QString theFile = QString::fromStdString(file);

    QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
                                            theFile, Qt::MatchExactly, 0);

    qDebug() << "in onReadFileComplete : " << theFile;

    if (!widgetList.empty())
    {
      QTreeWidgetItem* theWidget = widgetList[0];
      ui_.driveTreeWidget->editItem(theWidget, 1);
      theWidget->setText(1, tr("Local"));

      qDebug() << "widgetList not empty";
    }
  } else {
    qDebug() << "onReadFileFailed";
  }
}

/*void FileBrowser::onWatchedFileChanged(const QString& path) {
  qDebug() << "onWatchedFileChanged : " << path;
  std::string file = path.toStdString();
  file.erase(0,file.find_last_of("/")+1);
  QString theFile = QString::fromStdString(file);

  QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
                                            theFile, Qt::MatchExactly, 0);

  qDebug() << "in onWatchedFileChanged : File to modify" << theFile;

  if (!widgetList.empty())
  {
    QTreeWidgetItem* theWidget = widgetList[0];
    ui_.driveTreeWidget->editItem(theWidget, 1);
    //theWidget->setText(1, "Edited");
  } else {
    qDebug() << "onWatchFileChanged : no file matched" << theFile;
  }
}*/

void FileBrowser::onSaveFileCompleted(int success, const QString& filepath) {
  qDebug() << "onSaveFileCompleted : " << filepath;
  if (success != -1) {
    std::string dir = filepath.toStdString();
    dir.erase(0,1);
//    theWatcher_->removePath(rootPath_ + QString::fromStdString(dir));

    std::string fullFilePath = rootPath_.toStdString() + filepath.toStdString();

    if (fs::exists(fullFilePath)) {
      try {
        fs::remove(fullFilePath);
        qDebug() << "Remove File Success:"
                 << QString::fromStdString(fullFilePath);
      }
      catch(const std::exception&) {
        qDebug() << "Remove File failure:"
                 << QString::fromStdString(fullFilePath);
      }
    }

    std::string file = filepath.toStdString();
    file.erase(0,file.find_last_of("/")+1);
    QString theFile = QString::fromStdString(file);

    QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
                                            theFile, Qt::MatchExactly, 0);

    qDebug() << "in onSaveFileCompleted : " << theFile;

    if (!widgetList.empty())
    {
      QTreeWidgetItem* theWidget = widgetList[0];
      ui_.driveTreeWidget->editItem(theWidget, 1);
      theWidget->setText(1, tr("Network"));

      qDebug() << "widgetList not empty";
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

  std::string fullFilePath = rootPath_.toStdString() + currentDir_.toStdString()
      + filename;

  QList<QTreeWidgetItem *> widgetList = ui_.driveTreeWidget->findItems(
      QString::fromStdString(filename), Qt::MatchExactly, 0);

  if(widgetList.isEmpty()) {
    fs::copy_file(filePath.toStdString(), fullFilePath);
    if (fs::exists(fullFilePath)){
      saveFileToNetwork(currentDir_ + QString::fromStdString(filename));
    } else {
      qDebug() << "CopyFile Failed";
    }
  } else {
    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::Warning);
    msgBox.setText(tr("A file with the same name already exists! Please rename "
                      "your file before uploading."));
    msgBox.exec();
  }
}

void FileBrowser::saveFileToNetwork(const QString& filePath){
    //start save thread
    SaveFileThread* sft = new SaveFileThread(filePath, this);
    connect(sft, SIGNAL(saveFileCompleted(int,const QString&)),
          this, SLOT(onSaveFileCompleted(int,const QString&)));
    sft->start();
}

void FileBrowser::onUploadClicked(bool){
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
                                        const QString& newfilepath){
  qDebug() << "in onRenameFileCompleted:" + newfilepath;
  if(success != -1){
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
  if(success != -1){
    qDebug() << "MakeDir Success";
    populateDirectory(currentDir_);
  }
}

void FileBrowser::onRemoveDirCompleted(int success, const QString& path) {
  qDebug() << "in onRemoveDirCompleted:" + path;
  if(success != -1){
    qDebug() << "RemoveDir Success";
    populateDirectory(currentDir_);
  }
}

bool FileBrowser::eventFilter(QObject *obj, QEvent *event) {
  if (obj == ui_.driveTreeWidget->viewport()) {
    if (event->type() == QEvent::ContextMenu) {
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
    // TODO Get lang from ClientController and Update as Neccesary
    //ui_.retranslateUi(this);
  } else
    QWidget::changeEvent(event);
}
