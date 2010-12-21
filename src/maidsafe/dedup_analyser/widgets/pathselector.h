#ifndef PATHSELECTOR_H
#define PATHSELECTOR_H

#include <QWidget>

namespace Ui {
    class PathSelector;
}

class QFileSystemModel;

class PathSelector : public QWidget
{
    Q_OBJECT

public:
    explicit PathSelector(QWidget *parent = 0);
    ~PathSelector();

signals:
    void analyseNow();    

private:
    /* 
    * allocates memory for members
    */
    void createViewItems();

    /*
    * Filters dupes before adding to list
    */
    void addItemToList(QString);

    private slots:
        void itemSelected();
        void itemDeselected();

private:
    Ui::PathSelector *ui;
    QFileSystemModel *fileModel_;
};

#endif // PATHSELECTOR_H
