/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Locate and allow selection of drives and paths
* Version:      1.0
* Created:      2010, 21 / 12
* Revision:     none
* Author:       Saidle 
* Company:      Sigmoid Solutions 
*
* The following source code is property of Sigmoid Solutions and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.sigmoidsolutions.com
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of Sigmoid
* Solutions.
* ============================================================================
*/
#include <boost/filesystem/path.hpp>
#include <QFileSystemModel>
#include <QDebug>
#include "maidsafe/dedup_analyser/widgets/pathselector.h"
#include "ui_pathselector.h"  // NOLINT (Fraser) - This is generated during
                              // CMake and exists outwith normal source dir.

namespace fs3 = boost::filesystem3;

namespace maidsafe {

const int kNameColumnWidth = 200;

PathSelectorWidget::PathSelectorWidget(QWidget *parent)
    : QWidget(parent),
      ui_path_selector_(new Ui::PathSelector),
      file_model_() {
  ui_path_selector_->setupUi(this);
  QObject::connect(ui_path_selector_->buttonStartAnalyser, SIGNAL(clicked()),
                   this, SLOT(AnalyseButtonClicked()));
  QObject::connect(ui_path_selector_->selectButton, SIGNAL(clicked()), this,
                   SLOT(AddItemsClicked()));
  QObject::connect(ui_path_selector_->deselectButton, SIGNAL(clicked()), this,
                   SLOT(RemoveItemsClicked()));
  QObject::connect(ui_path_selector_->exitDedup, SIGNAL(clicked()), this,
                   SIGNAL(ExitDedupAnalyser()));
  CreateViewItems();
}

void PathSelectorWidget::CreateViewItems() {
  try {
    // tree view stuff goes here
    file_model_.reset(new QFileSystemModel);
    file_model_->setRootPath(QDir::rootPath());
    file_model_->setFilter(
        QDir::NoDotAndDotDot | QDir::Dirs | QDir::NoSymLinks);

    ui_path_selector_->treeView->setModel(file_model_.get());

    ui_path_selector_->treeView->setColumnWidth(0, kNameColumnWidth);
    // hide the "size" column
    ui_path_selector_->treeView->hideColumn(1);
    ui_path_selector_->treeView->setSelectionMode(
        QAbstractItemView::MultiSelection);
    ui_path_selector_->treeView->setDragEnabled(true);

    // list widget stuff goes here
    ui_path_selector_->selectedPathlistWidget->setDropIndicatorShown(true);
    ui_path_selector_->selectedPathlistWidget->setAcceptDrops(true);
    ui_path_selector_->selectedPathlistWidget->setSelectionMode(
        QAbstractItemView::MultiSelection);

    // analyse button stuff
    ui_path_selector_->buttonStartAnalyser->setEnabled(false);
  }
  catch(...) {
    qDebug() << "\nError in PathSelectorWidget::createViewItems()";
  }
}

void PathSelectorWidget::AddItemsClicked() {
  // add items to list widget
  QModelIndexList index_list =
      ui_path_selector_->treeView->selectionModel()->selectedIndexes();
  foreach(QModelIndex index, index_list) {
    AddNonDupeItemToList(file_model_->filePath(index));
  }

  // remove child items if their parents already exists
  RemoveRedundantItems();

  UpdateAnalyseButton();

  // [NOTE - IN THE END] clear the selection in tree view
  ui_path_selector_->treeView->clearSelection();
}

void PathSelectorWidget::RemoveItemsClicked() {
  int count = ui_path_selector_->selectedPathlistWidget->count() - 1;
  // knock out the selected items from listwidget
  for (; count >= 0; --count) {
  if (ui_path_selector_->selectedPathlistWidget->item(count)->isSelected())
    delete ui_path_selector_->selectedPathlistWidget->takeItem(count);
  }

  UpdateAnalyseButton();
  // tried with QList<QListWidgetItem*> selection =
  //     ui_path_selector_->selectedPathlistWidget->selectedItems();
  // but I need index anyways to call takeItem.. removeItem, does nothing!
}

void PathSelectorWidget::AddNonDupeItemToList(const QString &new_item) {
  QList<QListWidgetItem*> found = ui_path_selector_->selectedPathlistWidget->
      findItems(new_item, Qt::MatchExactly);
  if (found.isEmpty()) {
    ui_path_selector_->selectedPathlistWidget->addItem(new_item);
  }
}

void PathSelectorWidget::RemoveRedundantItems() {
  for (int iter_x = ui_path_selector_->selectedPathlistWidget->count() - 1;
       iter_x >= 0; --iter_x) {
  // parent
  fs3::path par((ui_path_selector_->selectedPathlistWidget->
      item(iter_x))->text().toStdString());

  for (int iter_y = 0;
       iter_y < ui_path_selector_->selectedPathlistWidget->count();) {
    bool dupe_child = false;
    // child
    fs3::path child((ui_path_selector_->selectedPathlistWidget->
        item(iter_y))->text().toStdString());

    // check if child belongs to par at any level of hierarchy
    do {
      if (child.has_parent_path()) {
        // take the child one level up
        child = child.parent_path();

        if (child == par) {
          // we have a sub tree, dont add this item to list
          delete ui_path_selector_->selectedPathlistWidget->takeItem(iter_y);
          dupe_child = true;
          iter_x = ui_path_selector_->selectedPathlistWidget->count() - 1;
          iter_y = 0;
          break;
        }
      } else {  // child has no parent, its the top most
        ++iter_y;
        break;
      }
    } while (dupe_child == false);
    }
  }
}

void PathSelectorWidget::UpdateAnalyseButton() {
  // checks if list widget is empty and updates the button
  if (ui_path_selector_->selectedPathlistWidget->count() == 0)
    ui_path_selector_->buttonStartAnalyser->setEnabled(false);
  else
    ui_path_selector_->buttonStartAnalyser->setEnabled(true);
}

void PathSelectorWidget::AnalyseButtonClicked() {
  // create a list for passing to DedupMainWindow
  std::vector<fs3::path> dirs;
  for (int iter = 0; iter < ui_path_selector_->selectedPathlistWidget->count();
       ++iter) {
    dirs.push_back(ui_path_selector_->selectedPathlistWidget->item(iter)->
        text().toStdString());
  }
  emit AnalyseNow(dirs);
}

}  // namespace maidsafe
