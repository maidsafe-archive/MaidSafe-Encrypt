#include "pathselector.h"
#include "ui_pathselector.h"
#include <QFileSystemModel>
#include <QDebug>
#include <boost/filesystem/path.hpp>

const int NAME_COL_WID = 200;

PathSelector::PathSelector(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PathSelector), fileModel_(NULL)
{
    ui->setupUi(this);

    QObject::connect(this->ui->buttonStartAnalyser, SIGNAL(clicked()),
        this, SIGNAL(analyseNow()));
    QObject::connect(ui->selectButton, SIGNAL(clicked()),
        this, SLOT(itemSelected()));
    QObject::connect(ui->deselectButton, SIGNAL(clicked()),
        this, SLOT(itemDeselected()));

    createViewItems();
}

PathSelector::~PathSelector()
{
    delete ui;
}

void PathSelector::createViewItems()
{
    try {
        //tree view stuff goes here
        fileModel_ = new QFileSystemModel;
        fileModel_->setRootPath(QDir::rootPath());
        fileModel_->setFilter(QDir::NoDotAndDotDot | QDir::Dirs | QDir::NoSymLinks );
        
        this->ui->treeView->setModel(fileModel_);

        ui->treeView->setColumnWidth(0, NAME_COL_WID);
        // hide the "size" column
        ui->treeView->hideColumn(1);
        ui->treeView->setSelectionMode(QAbstractItemView::MultiSelection);
        ui->treeView->setDragEnabled(true);

        // list widget stuff goes here
        ui->selectedPathlistWidget->setDropIndicatorShown(true);
        ui->selectedPathlistWidget->setAcceptDrops(true);
        ui->selectedPathlistWidget->setSelectionMode(QAbstractItemView::ContiguousSelection);
    } catch (...) {
        qDebug() << "\nError in PathSelector::createViewItems()";
    }
}

void PathSelector::itemSelected()
{
    QModelIndexList list = ui->treeView->selectionModel()->selectedIndexes();
    foreach(QModelIndex index, list) {
        addItemToList(fileModel_->filePath(index));
    }
}

void PathSelector::itemDeselected()
{
}

void PathSelector::addItemToList(QString aItem)
{
    QList<QListWidgetItem*> found = ui->selectedPathlistWidget->findItems(aItem, Qt::MatchExactly);
    
    // add the new item on the conditions that
    // 1 its not already present
    // 2 its parent is not present

    // condition - 1
    if (found.isEmpty()) {
        ui->selectedPathlistWidget->addItem(aItem);   
        /*
        // no exact match found
        // now check if parent exists

        boost::filesystem3::path child(aItem.toStdString());
        
        // check each item from list widget 
        // as a possible parent of child

        ui->selectedPathlistWidget->addItem(aItem);        
        */
    }
}