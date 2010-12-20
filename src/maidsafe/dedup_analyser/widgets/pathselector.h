#ifndef PATHSELECTOR_H
#define PATHSELECTOR_H

#include <QWidget>

namespace Ui {
    class PathSelector;
}

class PathSelector : public QWidget
{
    Q_OBJECT

public:
    explicit PathSelector(QWidget *parent = 0);
    ~PathSelector();

private:
    Ui::PathSelector *ui;
};

#endif // PATHSELECTOR_H
