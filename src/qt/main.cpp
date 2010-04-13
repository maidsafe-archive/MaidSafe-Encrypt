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

// qt
#include <QApplication>
#include <QTranslator>
#include <QLibraryInfo>
#include <QDebug>

// local
#include "qt/perpetual_data.h"
#include "widgets/system_tray_icon.h"
#include "client/client_controller.h"

void pdMessageOutput(QtMsgType type, const char* msg) {
  switch (type) {
    case QtDebugMsg:    printf("Debug: %s\n", msg);
                        break;
    case QtWarningMsg:  printf("Warning: %s\n", msg);
                        break;
    case QtCriticalMsg: printf("Critical: %s\n", msg);
                        break;
    case QtFatalMsg:    printf("Fatal: %s\n", msg);
                        abort();
  }
}

int main(int argc, char *argv[]) {
  qInstallMsgHandler(pdMessageOutput);

  //Set up Internationalization
  QApplication app(argc, argv);

  QTranslator qtTranslator;
  qtTranslator.load("qt_" + QLocale::system().name(),
             QLibraryInfo::location(QLibraryInfo::TranslationsPath));
  app.installTranslator(&qtTranslator);

  QTranslator myappTranslator;
  bool res = myappTranslator.load(":/translations/pd_translation_de_test.qm");
  app.installTranslator(&myappTranslator);

  qDebug() << "Translate Result"  << res;

  app.setOrganizationDomain("maidsafe.net");
  app.setOrganizationName("MaidSafe");
  app.setApplicationName("Perpetual Data");
  app.setApplicationVersion("0.1");

  SystemTrayIcon::instance()->show();

  // initialise client controller
  ClientController::instance();

  // the main application window
  PerpetualData pd;
  pd.show();

  // apply style sheet

  QFile file(":/qss/defaultWithWhite1.qss");
  file.open(QFile::ReadOnly);
  QString styleSheet = QLatin1String(file.readAll());

  qApp->setStyleSheet(styleSheet);

  // keep the application running in the tray when the window is closed
  app.setQuitOnLastWindowClosed(false);

  QObject::connect(SystemTrayIcon::instance(), SIGNAL(quit()),
                   &pd,                        SLOT(quit()));
  QObject::connect(SystemTrayIcon::instance(), SIGNAL(open()),
                   &pd,                        SLOT(show()));
  QObject::connect(SystemTrayIcon::instance(), SIGNAL(close()),
                   &pd,                        SLOT(hide()));

  int rv = app.exec();

  // finalize client controller
  ClientController::instance()->shutdown();

  SystemTrayIcon::instance()->hide();

  return rv;
}
