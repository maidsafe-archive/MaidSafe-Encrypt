#include "pathselector.h"
#include "ui_pathselector.h"

PathSelector::PathSelector(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PathSelector)
{
    ui->setupUi(this);
}

PathSelector::~PathSelector()
{
    delete ui;
}
