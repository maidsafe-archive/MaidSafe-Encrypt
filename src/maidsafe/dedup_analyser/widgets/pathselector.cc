#include "pathselector.h"
#include "ui_pathselector.h"

PathSelector::PathSelector(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PathSelector)
{
    ui->setupUi(this);

    QObject::connect(this->ui->buttonStartAnalyser, SIGNAL(clicked()),
        this, SIGNAL(analyseNow()));
}

PathSelector::~PathSelector()
{
    delete ui;
}
