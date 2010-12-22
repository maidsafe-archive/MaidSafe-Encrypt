#include "pathselector.h"
#include "ui_pathselector.h"
#include <QFileSystemModel>
#include <QDebug>
#include "boost/fileSystem/path.hpp"

const int NAME_COL_WID = 200;

PathSelector::PathSelector(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PathSelector), fileModel_(NULL)
{
    ui->setupUi(this);

    QObject::connect(this->ui->buttonStartAnalyser, SIGNAL(clicked()),
        this, SIGNAL(analyseNow()));
    QObject::connect(ui->selectButton, SIGNAL(clicked()),
        this, SLOT(addItemsClicked()));
    QObject::connect(ui->deselectButton, SIGNAL(clicked()),
        this, SLOT(removeItemsClicked()));
    QObject::connect(ui->exitDedup, SIGNAL(clicked()),
        this, SIGNAL(exitDedupAnalyser()));

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
        ui->selectedPathlistWidget->setSelectionMode(QAbstractItemView::MultiSelection);
    } catch (...) {
        qDebug() << "\nError in PathSelector::createViewItems()";
    }
}

void PathSelector::addItemsClicked()
{
    // add items to list widget
    QModelIndexList list = ui->treeView->selectionModel()->selectedIndexes();
    foreach(QModelIndex index, list) {
        addNonDupeItemToList(fileModel_->filePath(index));
    }

    // remove child items if their parents already exists
    removeRedundantItems();
    

    // [NOTE - IN THE END] clear the selection in tree view
    ui->treeView->clearSelection();
}

void PathSelector::removeItemsClicked()
{
    int count = ui->selectedPathlistWidget->count() - 1;
    
    // knock out the selected items from listwidget
    
    for (; count >= 0; --count) {
        if (ui->selectedPathlistWidget->item(count)->isSelected()) 
            delete ui->selectedPathlistWidget->takeItem(count);
    }

    // tried with QList<QListWidgetItem*> selection = ui->selectedPathlistWidget->selectedItems();
    // but I need index anyways to call takeItem.. removeItem, does nothing!
}

void PathSelector::addNonDupeItemToList(const QString &aItem)
{
    QList<QListWidgetItem*> found = ui->selectedPathlistWidget->findItems(aItem, Qt::MatchExactly);
    
    if (found.isEmpty()) {
        ui->selectedPathlistWidget->addItem(aItem);
    }
}


void PathSelector::removeRedundantItems()
{

    for (int iterX = ui->selectedPathlistWidget->count()-1; iterX >= 0; --iterX) {
        //parent                     
        boost::filesystem3::path par((ui->selectedPathlistWidget->item(iterX))->text().toStdString());

        for (int iterY = 0; iterY < ui->selectedPathlistWidget->count(); ) {
            bool dupeChild = false;
            // child
            boost::filesystem3::path child((ui->selectedPathlistWidget->item(iterY))->text().toStdString());
           
            // check if child belongs to par at any level of hierarchy
            do {
                if (child.has_parent_path()) {
                    // take the child one level up
                    child = child.parent_path();
                    
                    if (child == par) {
                        // we have a sub tree, dont add this item to list
                        delete ui->selectedPathlistWidget->takeItem(iterY);
                        dupeChild = true; 
                        iterX = ui->selectedPathlistWidget->count()-1;
                        iterY = 0;
                        break;
                    }
                } else { //child has no parent, its the top most 
                    ++iterY;
                    break;
                }
            } while(dupeChild == false);
        }
    }
}
