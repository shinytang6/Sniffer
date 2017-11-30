#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread.h>
#include <QTreeView>
#include "sniffer.h"
#include "maintreeview.h"

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread();
    Sniffer *sniffer;
    MainTreeView *mainTree ;
protected:
    void run();
signals:
   void  sendData(QString str1,QString str2,QString str3,QString str4);

};

#endif // CAPTURETHREAD_H
