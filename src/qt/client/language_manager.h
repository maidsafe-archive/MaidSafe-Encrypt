#ifndef QT_CLIENT_LANGUAGE_MANAGER_H_
#define QT_CLIENT_LANGUAGE_MANAGER_H_

#include <QTranslator>
#include <QLibraryInfo>

class LanguageManager : public QObject {
  Q_OBJECT
 public:
 QTranslator qtTranslator;
 QTranslator myappTranslator;

 bool getTranslators();
 bool

}

#endif // QT_CLIENT_LANGUAGE_MANAGER_H_
