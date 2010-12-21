#include "dedupmainwindow.h"
#include "ui_dedupmainwindow.h"
#include "pathselector.h"
#include "analyser.h"
#include <QDebug>

DedupMainWindow::DedupMainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::DedupMainWindow),
    mState(STATE_NULL), pathSelector_(NULL), analyser_(NULL)
{
    setWindowIcon(QPixmap(":/icons/32/ms_icon_blue.gif"));
    ui->setupUi(this);
    createAndAddStackedWidgets();
    setState(PATH_SELECT);
    setupConnections();    
}

DedupMainWindow::~DedupMainWindow()
{
    delete ui;
}

void DedupMainWindow::setState(State aState)
{
    switch (aState) {
        case PATH_SELECT:
            {
                // call state handler
                if (handlePathSelectState() == KERROR_NONE) {

                    // successfully changed state
                    mState = aState;
                }
            }
            break;

        case ANALYSE:
            {
                // call state handler
                if (handleAnalyseState() == KERROR_NONE) {
                    
                    // successfully changed state
                    mState = aState;
                }
            }
            break;

        case REPORT:
            {
                // call state handler
                if (handleReportState() == KERROR_NONE) { 
                    
                    // successfully changed state
                    mState = aState;
                }
            }
            break;

        default:
            break;
    }
}


DedupMainWindow::ErrorVal DedupMainWindow::handlePathSelectState()
{
    ErrorVal ret = KERROR_NONE; 

    try {
        // show the path select widget
        this->ui->stackedWidget->setCurrentWidget(pathSelector_);
    } catch (...) {
        ret = KERROR_WIDGET_DISPLAY;
    }

    return ret;
}


DedupMainWindow::ErrorVal DedupMainWindow::handleAnalyseState()
{
    ErrorVal ret = KERROR_NONE;

    try {
        // show the analyser widget now
        this->ui->stackedWidget->setCurrentWidget(analyser_);
    } catch (...) {
        ret = KERROR_WIDGET_DISPLAY;
    }

    return ret;
}

DedupMainWindow::ErrorVal DedupMainWindow::handleReportState()
{
   ErrorVal ret = KERROR_NONE;


   return ret;
}

void DedupMainWindow::createAndAddStackedWidgets()
{
    try {
        pathSelector_   = new PathSelector(this);
        analyser_       = new Analyser(this);
        this->ui->stackedWidget->addWidget(pathSelector_);
        this->ui->stackedWidget->addWidget(analyser_);
    } catch (...) {
        qDebug() << "\nError in DedupMainWindow::createStackedWidgets";
    }
}

void DedupMainWindow::setupConnections()
{
    QObject::connect(pathSelector_, SIGNAL(analyseNow()),
        this, SLOT(validatePathSelection()));
}

void DedupMainWindow::validatePathSelection()
{
    // TODO: do validation of any sort.. skipping at the moment
    setState(ANALYSE);
}