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

#ifndef FILE_BROWSER_H_INCLUDED
#define FILE_BROWSER_H_INCLUDED

#include "ui_file_browser.h"

#include <QMenu>
#include <QAction>
#include <QFileSystemModel>
#include <QFileSystemWatcher>

class FileBrowser : public QDialog {
  Q_OBJECT
 public:
  explicit FileBrowser(QWidget* parent = 0);
  virtual ~FileBrowser();

  virtual void setActive(bool active);
  virtual void reset();

  signals:
    void smilyChosen(int, int);

 private:
  Ui::FileBrowserPage ui_;
  //QFileSystemModel* model_;
  QFileSystemWatcher* theWatcher_;
  bool init_;
  QString currentDir_;
  QString rootPath_;
  QMenu *menu;
  QAction *openFile;
  QAction *sendFile;
  QAction *copyFile;
  QAction *cutFile;
  QAction *deleteFile;
  QAction *renameFile;
  QAction *saveFile;
  QAction *newFolder;

  int populateDirectory(const QString);
  void uploadFileFromLocal(const QString& filePath);
  void saveFileToNetwork(const QString& filePath);

  protected:
  void dropEvent(QDropEvent *event);
  void dragEnterEvent(QDragEnterEvent *event);
  void mousePressEvent(QMouseEvent *event);
  bool eventFilter(QObject *obj, QEvent *ev);

  private slots:
  void onItemDoubleClicked(QTreeWidgetItem*, int);
  void onMousePressed(QTreeWidgetItem* item, int column);
  void onReadFileCompleted(int success, const QString& filepath);
  void onSaveFileCompleted(int success, const QString& filepath);
  void onMakeDirectoryCompleted(int success, const QString& dir);
  void onRemoveDirCompleted(int success, const QString& path);
  void onRenameFileCompleted(int success, const QString& filepath,
                                          const QString& newfilepath);
  void onWatchedFileChanged(const QString& path);
  void onOpenFileClicked();
  void onSendFileClicked();
  void onCopyFileClicked();
  void onCutFileClicked();
  void onDeleteFileClicked();
  void onRenameFileClicked();
  void onSaveFileClicked();
  void onNewFolderClicked();
  void onBackClicked(bool);
  void onUploadClicked(bool);

};

#endif // FILE_BROWSER_H_INCLUDED
