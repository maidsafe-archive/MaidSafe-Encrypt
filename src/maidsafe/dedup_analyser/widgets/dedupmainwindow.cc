/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Detail window for dedup application
* Version:      1.0
* Created:      2010, 21 / 12
* Revision:     none
* Author:       Saidle
* Company:      Sigmoid Solutions
*
* The following source code is property of Sigmoid Solutions and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.sigmoidsolutions.com
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of Sigmoid
* Solutions.
* ============================================================================
*/
#include <QDebug>
#include "dedupmainwindow.h"
#include "ui_dedupmainwindow.h"
#include "pathselector.h"
#include "analyser.h"


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
    // We can use boost filesystem to check all drives and dirs (paths) exist
    
    setState(ANALYSE);
}