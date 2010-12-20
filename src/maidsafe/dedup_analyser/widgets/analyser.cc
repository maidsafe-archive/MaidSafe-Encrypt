#include "analyser.h"
#include "ui_analyser.h"

Analyser::Analyser(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Analyser)
{
    ui->setupUi(this);
}

Analyser::~Analyser()
{
    delete ui;
}
