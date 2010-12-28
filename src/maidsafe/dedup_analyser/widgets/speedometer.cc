#include "speedometer.h"

#include <qpainter.h>
#include "qwt_dial_needle.h"

namespace maidsafe {

Speedometer::Speedometer(QWidget *parent):
  QwtDial(parent),
  speedometer_label_(tr("deduplication meter")) {

  setWrapping(false);
  setReadOnly(true);

  setOrigin(135.0);
  setScaleArc(0.0, 270.0);

  scaleDraw()->setSpacing(8);

  QwtDialSimpleNeedle *needle = new QwtDialSimpleNeedle(
          QwtDialSimpleNeedle::Arrow, true, Qt::red,
          QColor(Qt::gray).light(130));
  setNeedle(needle);

  setScaleOptions(ScaleBackbone | ScaleTicks | ScaleLabel);
  setScaleTicks(0, 4, 8);
  scaleDraw()->setPenWidth(3);
}

void Speedometer::setLabel(const QString &label) {
  speedometer_label_ = label;
  update();
}

QString Speedometer::label() const {
  return speedometer_label_;
}

void Speedometer::drawScaleContents(QPainter *painter,
    const QPoint &center, int radius) const {
  QRect rect(0, 0, 2 * radius, 2 * radius - 10);
  rect.moveCenter(center);
  const QColor color =

#if QT_VERSION < 0x040000
  colorGroup().text();
#else
  palette().color(QPalette::Text);
#endif
  painter->setPen(color);

  const int flags = Qt::AlignBottom | Qt::AlignHCenter;
  painter->drawText(rect, flags, speedometer_label_);
}

} //  namespace maidsafe
