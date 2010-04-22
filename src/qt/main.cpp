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

// google crash reporter
#if defined(MAIDSAFE_LINUX)
  #include <google/breakpad/common/linux/linux_syscall_support.h>
  #include <google/breakpad/client/linux/handler/exception_handler.h>
#elif defined(__MSVC__)
  #include <client/windows/handler/exception_handler.h>
#endif

#if defined(MAIDSAFE_LINUX)
static bool DumpCallback(const char*,
                         const char *dump_id,
                         void*,
                         bool succeeded) {
  if (succeeded) {
    printf("%s is dumped.\n", dump_id);
  }
  return succeeded;
}
#elif defined(__MSVC__)
static bool DumpCallback(const wchar_t*,
                         const wchar_t* minidump_id,
                         void*,
                         EXCEPTION_POINTERS*,
                         MDRawAssertionInfo*,
                         bool succeeded) {
  if (succeeded) {
    wprintf(L"%s is dumped.\n", minidump_id);
  }
  return succeeded;
}
#endif

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
#ifdef MAIDSAFE_LINUX
  google_breakpad::ExceptionHandler eh(".", NULL, DumpCallback, NULL, true);
#elif defined(__MSVC__)
  google_breakpad::ExceptionHandler eh(L".", NULL, DumpCallback,
      NULL, google_breakpad::ExceptionHandler::HANDLER_ALL);
#endif
  qInstallMsgHandler(pdMessageOutput);

  //Set up Internationalization
  QApplication app(argc, argv);

  app.setOrganizationDomain("http://www.maidsafe.net");
  app.setOrganizationName("maidsafe.net Ltd.");
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
