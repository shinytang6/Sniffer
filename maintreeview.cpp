#include "maintreeview.h"
#include <QStandardItem>
#include <QStandardItemModel>

MainTreeView::MainTreeView(QTreeView *treeView)
{

    QStandardItemModel *mainModel;

    mainModel = new QStandardItemModel();
    mainModel->setColumnCount(6);
    mainModel->setHeaderData(0, Qt::Horizontal, tr("序号"));
    mainModel->setHeaderData(1, Qt::Horizontal, tr("时间"));
    mainModel->setHeaderData(2, Qt::Horizontal, tr("源IP地址"));
    mainModel->setHeaderData(3, Qt::Horizontal, tr("目标IP地址"));
    mainModel->setHeaderData(4, Qt::Horizontal, tr("协议"));
    mainModel->setHeaderData(5, Qt::Horizontal, tr("发送长度"));
    treeView->setModel(mainModel);

//    QStandardItem *item;
//    item = new QStandardItem("5");
//    mainModel->setItem(0, 0, item);

//    item = new QStandardItem("hah");
//    mainModel->setItem(0, 1, item);
//     item = new QStandardItem("127.0.1.1");
//        mainModel->setItem(0, 2, item);
//        item = new QStandardItem("197.235.5.2");
//        mainModel->setItem(0, 3, item);
//        item = new QStandardItem("ip");
//        mainModel->setItem(0, 4, item);
//        item = new QStandardItem("20");
//        mainModel->setItem(0, 5, item);

}

MainTreeView::~MainTreeView()
{

}

void MainTreeView::addOneCaptureItem()
{
        QStandardItem *item;
        item = new QStandardItem("5");
        mainModel->setItem(0, 0, item);

        item = new QStandardItem("hah");
        mainModel->setItem(0, 1, item);
         item = new QStandardItem("127.0.1.1");
            mainModel->setItem(0, 2, item);
            item = new QStandardItem("197.235.5.2");
            mainModel->setItem(0, 3, item);
            item = new QStandardItem("ip");
            mainModel->setItem(0, 4, item);
            item = new QStandardItem("20");
            mainModel->setItem(0, 5, item);
}

