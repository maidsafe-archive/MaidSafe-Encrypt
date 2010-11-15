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
 *  Created on: May 17, 2010
 *      Author: Stephen
 */
#include "maidsafe/lifestuff/client/big_list_delegate.h"

#include <QtGui>
#include <QApplication>	

BigListDelegate::BigListDelegate(QObject *parent)
     : QAbstractItemDelegate(parent) {
     pixelSize = 12;
 }

void BigListDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                            const QModelIndex &index) const {

  if(qVariantCanConvert<QString>(index.data())) {

    QString data = qVariantValue<QString>(index.data());
    QRect rect(option.rect.topLeft(),QSize(32,32));

    QApplication::style()->drawItemPixmap(painter, rect, Qt::AlignLeft, icon_);

    rect.moveTo(rect.topRight());

    QApplication::style()->drawItemText(painter, rect, Qt::AlignLeft, option.palette, true, data);
  }
}

BigListDelegate::~BigListDelegate() { }

QSize BigListDelegate::sizeHint(const QStyleOptionViewItem & /* option */,
                               const QModelIndex & /* index */) const {
  return QSize(pixelSize, pixelSize);
}

void BigListDelegate::setPixelSize(int size) {
  pixelSize = size;
}