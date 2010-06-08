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

#ifndef QT_WIDGETS_FILE_BROWSER_H_
#define QT_WIDGETS_FILE_BROWSER_H_

#include <boost/shared_ptr.hpp>

#include <QAction>
#include <QFileSystemModel>
#include <QFileSystemWatcher>
#include <QMenu>
#include <QProcess>
#include <QPixmap>

#include "maidsafe/client/clientcontroller.h"
#include "qt/client/big_list_delegate.h"

#include "ui_file_browser.h"

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
  bool init_;
  BigListDelegate* bigListDelegate_;
  QString rootPath_;
  QString currentDir_;
  QString currentTreeDir_;
  QString viewType_;

  QMenu *menu;
  QAction *openFile;
  QAction *openWith;
  QAction *sendFile;
  QAction *copyFile;
  QAction *cutFile;
  QAction *deleteFile;
  QAction *renameFile;
  QAction *saveFile;

  QMenu *menu2;
  QMenu *view;
  QMenu *sort;
  QActionGroup* viewGroup;
  QActionGroup* sortGroup;
  QAction *newFolder;
  QAction *tilesMode;
  QAction *listMode;
  QAction *bigListMode;
  QAction *detailMode;
  QAction *iconMode;
  QAction *nameSort;
  QAction *sizeSort;
  QAction *typeSort;
  QAction *dateSort;

    enum ViewMode {
    TILES,
    DETAIL,
    LIST,
    BIGLIST,
    SMALLICONS
    };

  void setViewMode(ViewMode viewMode);
  ViewMode viewMode_;

  boost::shared_ptr<QProcess> myProcess_;

  QIcon getAssociatedIconFromPath(const QString& filepath);
  QString getCurrentTreePath(QTreeWidgetItem* item);
  QString getFullFilePath(const QString& filepath);
  void createAndConnectActions();
  void populateDirectory(const QString);
  int createTreeDirectory(const QString);
  void uploadFileFromLocal(const QString& filePath);
  void saveFileToNetwork(const QString& filePath);
  void getTreeSubFolders(const QString);
  void openFileFromDir(const QString);
  void setMenuDirMenu();
  void setMenuFileMenu();
  void setMenuSortIconMenu();
  void setMenuSortDetailMenu();
  void setMenuSortNoFolderMenu();
  void setMenuReadOnlyMenu();
  int drawTileView();
  int drawDetailView();
  int drawListView();
  int drawIconView();

  protected:
    void dropEvent(QDropEvent *event);
    void dragEnterEvent(QDragEnterEvent *event);
    bool eventFilter(QObject *obj, QEvent *ev);
    void changeEvent(QEvent *event);

  private slots:
    void onItemDoubleClicked(QTreeWidgetItem*, int);
    void onListItemDoubleClicked(QListWidgetItem*);
    void onFolderItemPressed(QTreeWidgetItem*, int);
    void onIconMousePressed(QListWidgetItem*);
    void onMousePressed(QTreeWidgetItem* item, int column);
    void onItemExpanded(QTreeWidgetItem* item);
    void onReadFileCompleted(int success, const QString& filepath);
    void onSaveFileCompleted(int success, const QString& filepath);
    void onMakeDirectoryCompleted(int success, const QString& dir);
    void onRemoveDirCompleted(int success, const QString& path);
    void onRenameFileCompleted(int success, const QString& filepath,
                                            const QString& newfilepath);

    void onOpenFileClicked();
// #ifdef PD_APPLE // TODO (Alec): Find out why this throws
    void onOpenWithClicked();
    void onSendFileClicked();
    void onCopyFileClicked();
    void onCutFileClicked();
    void onDeleteFileClicked();
    void onRenameFileClicked();
    void onSaveFileClicked();
    void onNewFolderClicked();
    void onViewGroupClicked(QAction* action);
    void onSortGroupClicked(QAction* action);
    void onBackClicked(bool);
    void onUploadClicked(bool);
    void onOpenError(QProcess::ProcessError);
    void onOpenStarted();
    void onOpenFinished(int, QProcess::ExitStatus);
    // void onWatchedFileChanged(const QString& path);
};

#endif  // QT_WIDGETS_FILE_BROWSER_H_
