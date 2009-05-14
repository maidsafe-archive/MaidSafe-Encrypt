/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Mar 26, 2009
 *      Author: Team
 */

#ifndef QT_CREATE_OPTIONS_H_
#define QT_CREATE_OPTIONS_H_

// qt
#include <QWizardPage>

// generated
#include "ui_create_page_options.h"

class QWizardPage;

class CreateOptionsPage : public QWizardPage
{
    Q_OBJECT

public:
    CreateOptionsPage( QWidget* parent = 0 );
    virtual ~CreateOptionsPage();

    virtual void cleanupPage();

private:
    Ui::options ui_;
};

#endif // QT_CREATE_OPTIONS_H_

