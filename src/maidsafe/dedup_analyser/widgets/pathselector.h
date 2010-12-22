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
    void exitDedupAnalyser(); //signal from path selector

private:
    /* 
    * allocates memory for members
    */
    void createViewItems();

    /*
    * Filters children before adding to list
    * for duplicates
    */
    void addNonDupeItemToList(const QString&);

    /*
    * called after addNonDupeItemToList
    * removes child items if their parents exist
    */
    void removeRedundantItems();

private slots:
    void addItemsClicked();
    void removeItemsClicked();

private:
    Ui::PathSelector *ui;
    QFileSystemModel *fileModel_;
};

#endif // PATHSELECTOR_H
