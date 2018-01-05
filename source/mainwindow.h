#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "sniffer.h"
#include "capturethread.h"
#include "iostream"
#include <QSortFilterProxyModel>
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();


private slots:
    void on_startCapture_clicked();
    void receiveDetail(QList<QString> strList1,QList<QString> strList2,QList<QString> strList3,QList<QString> strList4);

    void receiveData(QString data1,QString data2,QString data3,QString data4,QString data5);
    void receiveDevs(pcap_if_t *alldevs);
    void on_stopCapture_clicked();
    bool on_saveData_clicked();

    void on_loadFile_clicked();
    void on_treeView_clicked(const QModelIndex &index);

    void on_search_clicked();

    void on_quit_clicked();

private:
    Ui::MainWindow *ui;
    Sniffer sniffer;
    QStandardItemModel *mainModel;
     QStandardItemModel *mainModel2;
    pcap_if_t *dev;
    int iPosition;
    int cnt;
//    int
    CaptureThread *capturethread;
    QList<QStringList> list1;
    QList<QStringList> list2;
    QList<QStringList> list3;
    QList<QStringList> list4;

    QSortFilterProxyModel *sfmodel;
};

#endif // MAINWINDOW_H
