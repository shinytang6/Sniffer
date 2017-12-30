#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "capturethread.h"
#include "sniffer.h"
#include <QStandardItem>
#include <QTableWidget>
#include <QDebug>
#include <QTreeWidgetItem>
#include "pcap.h"
#include <QList>
#include <QMetaType>
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    capturethread = NULL;
    cnt = 0;
    qRegisterMetaType<QList<QString>> ("QList<QString>");
    qRegisterMetaType<QString> ("QString");
//    QStandardItemModel *mainModel;
    mainModel = new QStandardItemModel();
    mainModel->setColumnCount(6);
    mainModel->setHeaderData(0, Qt::Horizontal, tr("序号"));
    mainModel->setHeaderData(1, Qt::Horizontal, tr("时间"));
    mainModel->setHeaderData(2, Qt::Horizontal, tr("源IP地址"));
    mainModel->setHeaderData(3, Qt::Horizontal, tr("目标IP地址"));
    mainModel->setHeaderData(4, Qt::Horizontal, tr("协议"));
    mainModel->setHeaderData(5, Qt::Horizontal, tr("发送长度"));

    ui->treeView->setModel(mainModel);
    ui->treeView->setColumnWidth(0,50);
    ui->treeView->setColumnWidth(1,200);
    ui->treeView->setColumnWidth(2,200);
    ui->treeView->setColumnWidth(3,200);
    ui->treeView->setColumnWidth(4,200);
    ui->treeView->setColumnWidth(5,200);
//    ui->comboBox->addItem("dsa");

    mainModel2 = new QStandardItemModel();
//    mainModel2->setColumnCount(6);
//    mainModel2->setHeaderData(0, Qt::Horizontal, tr("序号"));
//    mainModel2->setHeaderData(1, Qt::Horizontal, tr("时间"));
//    mainModel2->setHeaderData(2, Qt::Horizontal, tr("源IP地址"));
//    mainModel2->setHeaderData(3, Qt::Horizontal, tr("目标IP地址"));
//    mainModel2->setHeaderData(4, Qt::Horizontal, tr("协议"));
//    mainModel2->setHeaderData(5, Qt::Horizontal, tr("发送长度"));
    ui->detailview->setModel(mainModel2);
//    ui->detailview->setColumnWidth(0,50);
//    ui->detailview->setColumnWidth(1,200);
//    ui->detailview->setColumnWidth(2,200);
//    ui->detailview->setColumnWidth(3,200);
//    ui->detailview->setColumnWidth(4,200);
//    ui->detailview->setColumnWidth(5,200);






    iPosition = 0;
//    CaptureThread *capturethread = new CaptureThread();
//     capturethread->start();
//     capturethread->sniffer = &sniffer;


     capturethread = new CaptureThread;
     capturethread->sniffer = &sniffer;
     capturethread->isStop = true;
     capturethread->start();
//     capturethread->devNum = ui->comboBox->currentIndex();
     connect(capturethread,SIGNAL(sendDevs(pcap_if_t *)),this,SLOT(receiveDevs(pcap_if_t *)));
     capturethread = NULL;
//    Sniffer *snif = new Sniffer;

//    connect(this,SIGNAL(sendData()),this,SLOT(receiveData()));
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
//    for (int row = 0; row < 4; ++row) {
//        for (int column = 0; column < 2; ++column) {
//            QModelIndex index = model->index(row, column, QModelIndex());
//            model->setItem(1,2, QVariant("dsasa"));
//        }
//    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_startCapture_clicked()
{

    if (capturethread != NULL) {
            return;
    }

    capturethread = new CaptureThread;
//    CaptureThread *capturethread = new CaptureThread();
    capturethread->sniffer = &sniffer;
    capturethread->isStop = false;
//    QString filter = ui->textEdit->toPlainText();
//    QByteArray ba = filter.toLatin1();
//    capturethread->filter = ba.data();
    capturethread->devNum = ui->comboBox->currentIndex();
    QString filter = ui->textEdit->toPlainText();
    capturethread->filter = filter;
//    QByteArray ba = filter.toLatin1();
//    capturethread->filter = ba.data();

    // 启动线程
    capturethread->start();
    connect(capturethread,SIGNAL(sendData(QString,QString,QString,QString,QString)),this,SLOT(receiveData(QString,QString,QString,QString,QString)),Qt::QueuedConnection);
    connect(capturethread,SIGNAL(sendDetail(QList<QString> )),this,SLOT(receiveDetail(QList<QString>)),Qt::QueuedConnection);
//    QString filter = ui->textEdit->toPlainText();
//    QByteArray ba = filter.toLatin1();
//    capturethread->filter = ba.data();
}

void MainWindow::receiveData(QString data1,QString data2,QString data3,QString data4,QString data5){

        QStandardItem *item;
        item = new QStandardItem(QString::number(iPosition+1, 10));
        mainModel->setItem(iPosition, 0, item);
        item = new QStandardItem(data1);
        mainModel->setItem(iPosition, 1, item);
        item = new QStandardItem(data2);
        mainModel->setItem(iPosition, 2, item);
        item = new QStandardItem(data3);
        mainModel->setItem(iPosition, 3, item);
        item = new QStandardItem(data4);
        mainModel->setItem(iPosition, 4, item);
        item = new QStandardItem(data5);
        mainModel->setItem(iPosition, 5, item);
        iPosition = iPosition + 1;

//        item = new QStandardItem(frame);
//        mainModel2->setItem(0, 0, item);
//        for(int i = 0; i < frame_list.count(); i++){
//                 QStandardItem* itemChild = new QStandardItem(frame_list[i]);
//                 item->appendRow(itemChild);
//        }

//        QStandardItem* itemProject = new QStandardItem(index.data().toString());
//        mainModel2->appendRow(itemProject);
//        QStandardItem* itemChild = new QStandardItem(QStringLiteral("length"));
//        itemProject->appendRow(itemChild);

//        QTreeWidgetItem *Item1 = new QTreeWidgetItem(mainModel2,QStringList(info_frame_bytes));
//                    for(int i = 0; i < info_frame_bytes_List.count(); i++)
//                    {
//                        QTreeWidgetItem *Item1_1 = new QTreeWidgetItem(Item1,QStringList(info_frame_bytes_List[i])); //子节点1_1
//                        Item1->addChild(Item1_1); //添加子节点
//                    }
}

void MainWindow::receiveDetail(QList<QString> strList){


//        QStandardItem *item;
//        item = new QStandardItem(str);
//        mainModel2->setItem(iPosition, 0, item);



//        for(int i = 0; i < strList.count(); i++)
//        {
//             QStandardItem *Item1_1 = new QStandardItem(strList[i]); //子节点1_1
//             item->appendRow(Item1_1); //添加子节点
//            qDebug()<<"detail:"<<strList[i]<<"\n";
//        }
//         std::cout<<"AAAAAAAAA:"<<str.toStdString()<<endl;
//            qDebug()<<"detail:"<<str<<"\n";
          list1.append(strList);
//        list2.append(strList2);
//        list3.append(strList3);



}


void MainWindow::receiveDevs(pcap_if_t *alldevs){
    for(dev= alldevs; dev != NULL; dev= dev->next)
    {
            ui->comboBox->addItem(dev->description);
    }
}

void MainWindow::on_stopCapture_clicked()
{
    capturethread->isStop = true;
}

void MainWindow::on_saveData_clicked()
{
//    capturethread = new CaptureThread;
//    capturethread->sniffer = &sniffer;
//    capturethread->isStop = true;
//    capturethread->start();
//    capturethread = NULL;
//    capturethread->tempFile ="G:/sniferTempData/snif.txt";
}



void MainWindow::on_loadFile_clicked()
{
        capturethread = new CaptureThread;
        capturethread->sniffer = &sniffer;
        capturethread->isStop = true;
        capturethread->start();
        capturethread = NULL;
//        capturethread->tempFile ="G:/sniferTempData/snif.txt";
}

void MainWindow::on_treeView_clicked(const QModelIndex &index)
{
//    printf("index is %d",index);
//    printf("\n");
//    printf("treview index is %s",ui->treeView->currentIndex().model());
//    QStandardItemModel* model = static_cast<QStandardItemModel*>(ui->treeView->model());
//    QModelIndex currentIndex = ui->treeView->currentIndex();
//    QStandardItem* currentItem = model->itemFromIndex(currentIndex);
//    QStandardItem *item;
//    item = new QStandardItem(ui->treeView->currentIndex().data());
//    mainModel2->setItem(0, 1,item);
//    QTreeWidgetItem *Item1 = new QTreeWidgetItem(ui->detailview,currentItem);
//     QStandardItem* itemProject = new QStandardItem(index.data().toString());
//     mainModel2->appendRow(itemProject);
//     QStandardItem* itemChild = new QStandardItem(QStringLiteral("length"));
//     itemProject->appendRow(itemChild);



//                    qDebug()<<"detail:"<<list2[ui->treeView->currentIndex().row()]<<"\n";


                    QStandardItem *item;
                    int row = ui->treeView->currentIndex().row();
                    int number = 0;
                    if(row>=1)
                        number = list1[row-1].count();

                    item = new QStandardItem(list1[row][number]);
                    mainModel2->setItem(0, 0, item);
                            for(int i = number+1; i < list1[row].count(); i++)
                            {
                                 QStandardItem *Item1_1 = new QStandardItem(list1[row][i]); //子节点1_1
                                 item->appendRow(Item1_1); //添加子节点;
                            }



//                   if(row>=1)
//                        number = list2[row-1].count();

//                   item = new QStandardItem(list2[row][number]);
//                   mainModel2->setItem(1, 0, item);
//                   for(int i = number+1; i < list2[row].count(); i++)
//                   {
//                       QStandardItem *Item1_1 = new QStandardItem(list2[row][i]); //子节点1_1
//                       item->appendRow(Item1_1); //添加子节点;
//                   }


//                   if(row>=1)
//                        number = list3[row-1].count();

//                   item = new QStandardItem(list3[row][number]);
//                   mainModel2->setItem(2, 0, item);
//                   for(int i = number+1; i < list3[row].count(); i++)
//                   {
//                       QStandardItem *Item1_1 = new QStandardItem(list3[row][i]); //子节点1_1
//                       item->appendRow(Item1_1); //添加子节点;
//                    }

//     QString str;
//     str += QStringLiteral("当前选中：%1\nrow:%2,column:%3\n").arg(index.data().toString())
//                           .arg(index.row()).arg(index.column());
//     str += QStringLiteral("父级：%1\n").arg(index.parent().data().toString());
//     ui->label_3->setText(str);
}
