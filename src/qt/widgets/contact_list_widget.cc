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
 *  Created on: May 19, 2009
 *      Author: Team
 */

#include "contact_list_widget.h"

// qt
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QPicture>

//
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"


ContactListWidget::ContactListWidget( QWidget* parent )
    : QWidget( parent )
    //, user_name_( user_name ), status_(status)
{


}

ContactListWidget::~ContactListWidget()
{
}



