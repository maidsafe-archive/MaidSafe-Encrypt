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
#include "qt/client/big_list_delegate.h"

#include <QtGui>
#include <QApplication>	

BigListDelegate::BigListDelegate(QObject *parent)
     : QAbstractItemDelegate(parent) {
     pixelSize = 12;
 }

void BigListDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                            const QModelIndex &index) const {

		int progress = index.data().toInt();
		
		QStyleOptionProgressBar progressBarOption;
    progressBarOption.rect = option.rect;
    progressBarOption.minimum = 0;
    progressBarOption.maximum = 100;
    progressBarOption.progress = progress;
    progressBarOption.text = QString::number(progress) + "%";
    progressBarOption.textVisible = true;
		
		QApplication::style()->drawControl(QStyle::CE_ProgressBar,
                                          &progressBarOption, painter);
}

BigListDelegate::~BigListDelegate() { }

QSize BigListDelegate::sizeHint(const QStyleOptionViewItem & /* option */,
                               const QModelIndex & /* index */) const {
	return QSize(pixelSize, pixelSize);
}

void BigListDelegate::setPixelSize(int size)
{
     pixelSize = size;
}