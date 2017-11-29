#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread.h>
#include <QTreeView>
#include "sniffer.h"

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread();
    Sniffer *sniffer;
    QTreeView *treeView;
protected:
    void run();


};

#endif // CAPTURETHREAD_H
