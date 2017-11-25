#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_startCapture_clicked()
{
    sniffer.findAllDevs();
    sniffer.openNetDev(6);
    sniffer.setDevsFilter("ip and udp");
    sniffer.captureOnce();
}

