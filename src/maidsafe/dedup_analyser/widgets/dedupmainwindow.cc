#include "dedupmainwindow.h"
#include "ui_dedupmainwindow.h"

DedupMainWindow::DedupMainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::DedupMainWindow)
{
    ui->setupUi(this);
}

DedupMainWindow::~DedupMainWindow()
{
    delete ui;
}
