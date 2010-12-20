#ifndef DEDUPMAINWINDOW_H
#define DEDUPMAINWINDOW_H

#include <QMainWindow>

namespace Ui {
    class DedupMainWindow;
}

class DedupMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit DedupMainWindow(QWidget *parent = 0);
    ~DedupMainWindow();

private:
    Ui::DedupMainWindow *ui;
};

#endif // DEDUPMAINWINDOW_H
