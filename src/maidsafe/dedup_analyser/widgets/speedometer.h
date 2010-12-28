#ifndef MAIDSAFE_DEDUP_ANALYSER_WIDGETS_SPEEDOMETER_H_
#define MAIDSAFE_DEDUP_ANALYSER_WIDGETS_SPEEDOMETER_H_

#include <QString>
#include "qwt_dial.h"

namespace maidsafe {

class Speedometer: public QwtDial {
public:
    Speedometer(QWidget *parent = NULL);

    void setLabel(const QString &);
    QString label() const;

protected:
    virtual void drawScaleContents(QPainter *painter,
        const QPoint &center, int radius) const;

private:
    QString speedometer_label_;
};

} //  namespace maidsafe
#endif //MAIDSAFE_DEDUP_ANALYSER_WIDGETS_SPEEDOMETER_H_
