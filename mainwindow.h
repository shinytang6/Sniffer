#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "sniffer.h"
#include "iostream"
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
    void receiveData(QString data1,QString data2,QString data3,QString data4,QString data5);
    void receiveDevs(pcap_if_t *alldevs);
private:
    Ui::MainWindow *ui;
    Sniffer sniffer;
    QStandardItemModel *mainModel;
    pcap_if_t *dev;
    int iPosition;

};

#endif // MAINWINDOW_H
