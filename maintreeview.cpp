//#include "maintreeview.h"
//#include "ui_mainwindow.h"
//#include <QStandardItem>
//#include <QTableWidget>
//MainTreeView::MainTreeView(QWidget *parent) :
//    QMainWindow(parent),
//    ui(new Ui::MainTreeView)
//{

//    QStandardItemModel *mainModel;

//    mainModel = new QStandardItemModel();
//    mainModel->setColumnCount(6);
//    mainModel->setHeaderData(0, Qt::Horizontal, tr("序号"));
//    mainModel->setHeaderData(1, Qt::Horizontal, tr("时间"));
//    mainModel->setHeaderData(2, Qt::Horizontal, tr("源IP地址"));
//    mainModel->setHeaderData(3, Qt::Horizontal, tr("目标IP地址"));
//    mainModel->setHeaderData(4, Qt::Horizontal, tr("协议"));
//    mainModel->setHeaderData(5, Qt::Horizontal, tr("发送长度"));
//    ui->treeView->setModel(mainModel);
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
////    for (int row = 0; row < 4; ++row) {
////        for (int column = 0; column < 2; ++column) {
////            QModelIndex index = model->index(row, column, QModelIndex());
////            model->setItem(1,2, QVariant("dsasa"));
////        }
////    }
//}

//MainTreeView::~MainTreeView()
//{
//    delete ui;
//}


