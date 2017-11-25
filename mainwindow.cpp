#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "capturethread.h"

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
    CaptureThread *capturethread = new CaptureThread();
    capturethread->sniffer = &sniffer;
    // 启动线程
    capturethread->start();
}

