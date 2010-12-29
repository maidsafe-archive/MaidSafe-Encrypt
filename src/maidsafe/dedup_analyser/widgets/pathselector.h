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
#ifndef PATHSELECTOR_H
#define PATHSELECTOR_H

#include <boost/filesystem.hpp>
#include <QWidget>

namespace fs3 = boost::filesystem3;

namespace Ui { class PathSelector; }

class QFileSystemModel;

namespace maidsafe {

class PathSelectorWidget : public QWidget {
  Q_OBJECT
 public:
  explicit PathSelectorWidget(QWidget *parent);
  ~PathSelectorWidget() {}
 signals:
  void AnalyseNow(std::vector<fs3::path>);  
  void ExitDedupAnalyser();  // signal from path selector
 private:
  /* 
  * allocates memory for members
  */
  void CreateViewItems();

  /*
  * Filters children before adding to list
  * for duplicates
  */
  void AddNonDupeItemToList(const QString&);

  /*
  * called after addNonDupeItemToList
  * removes child items if their parents exist
  */
  void RemoveRedundantItems();

  /*
  * enables or disables the analyse button
  */
  void UpdateAnalyseButton();
  boost::shared_ptr<Ui::PathSelector> ui_path_selector_;
  boost::shared_ptr<QFileSystemModel> file_model_;

 private slots:
  void AddItemsClicked();
  void RemoveItemsClicked();
  void AnalyseButtonClicked();
};

} //maidsafe
#endif // PATHSELECTOR_H
