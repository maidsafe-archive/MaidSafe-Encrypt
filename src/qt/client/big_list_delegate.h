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

// Delegate Class for displaying Big List View Items

#ifndef QT_CLIENT_BIG_LIST_DELEGATE_H_
#define QT_CLIENT_BIG_LIST_DELEGATE_H_

#include <QAbstractItemDelegate>
#include <QFontMetrics>
#include <QModelIndex>
#include <QSize>

class QAbstractItemModel;
class QObject;
class QPainter;

static const int ItemSize = 256;		

class BigListDelegate : public QAbstractItemDelegate {
     Q_OBJECT

 public:
     explicit BigListDelegate(QObject *parent = 0);
		 virtual ~BigListDelegate();

     void paint(QPainter *painter, const QStyleOptionViewItem &option,
                const QModelIndex &index) const;

     QSize sizeHint(const QStyleOptionViewItem &option,
                    const QModelIndex &index ) const;

 public slots:
     void setPixelSize(int size);

 private:
     int pixelSize;
		 QPixmap icon_;
		 QString text1, text2, text3;

 };

#endif