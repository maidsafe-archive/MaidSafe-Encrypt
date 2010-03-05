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

#ifndef QT_WIDGETS_SMILY_H_
#define QT_WIDGETS_SMILY_H_

#include "ui_smily.h"

class Smily : public QDialog {
  Q_OBJECT
 public:
  explicit Smily(QWidget* parent = 0);
  virtual ~Smily();

  signals:
    void smilyChosen(int, int);

 private:
  Ui::ChooseSmily ui_;

  private slots:
    void onCellDoubleClicked(int row, int column);
};


#endif  // QT_WIDGETS_SMILY_H_
