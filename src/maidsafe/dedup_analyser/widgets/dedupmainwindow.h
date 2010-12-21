#ifndef DEDUPMAINWINDOW_H
#define DEDUPMAINWINDOW_H

#include <QMainWindow>

namespace Ui {
    class DedupMainWindow;
}

class PathSelector;
class Analyser;

class DedupMainWindow : public QMainWindow
{
    Q_OBJECT

private:
    enum State {
        STATE_NULL,
        PATH_SELECT,
        ANALYSE,
        REPORT
    };

    enum ErrorVal {
        KERROR_NONE,
        KERROR_WIDGET_DISPLAY
    };

    State mState;  

public:
    explicit DedupMainWindow(QWidget *parent = 0);
    ~DedupMainWindow();
    
    inline State state(){return mState;}

private:
    // set the new state
    void setState(State);

    /*
    * handler for PATH_SELECT
    * returns ErrorVal 
    */
    ErrorVal handlePathSelectState();

    /*
    * handler for ANALYSE
    * returns ErrorVal
    */
    ErrorVal handleAnalyseState();

    /*
    * handler for REPORT
    * returns ErrorVal
    */
    ErrorVal handleReportState();  

    /*
    * create child widgets for dedup_analyser
    * adds them to DedupMainWindow
    */
    void createAndAddStackedWidgets();

    /* 
    * Qt connections between widgets
    */
    void setupConnections();

private slots:
    /* 
    * Checks if user selected paths are okay!
    */
    void validatePathSelection();

private:
    Ui::DedupMainWindow *ui;
    PathSelector        * pathSelector_;
    Analyser            * analyser_;
};

#endif // DEDUPMAINWINDOW_H

