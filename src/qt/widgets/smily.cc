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
 *  Created on: Feb 24, 2010
 *      Author: Stephen Alexander
 */

 #include "qt/widgets/smily.h"

 Smily::Smily(QWidget* parent){
    setWindowFlags( Qt::Popup);
      ui_.setupUi(this);
      adjustSize();

    connect(ui_.tableWidget, SIGNAL(cellDoubleClicked(int, int)),
         this,                 SLOT(onCellDoubleClicked(int, int)));
 }

 Smily::~Smily(){
 }

 void Smily::onCellDoubleClicked(int row, int column){
   emit smilyChosen(row,column);
    this->close();
 }


