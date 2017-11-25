#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread.h>
#include "sniffer.h"

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread();
    Sniffer *sniffer;
protected:
    void run();


};

#endif // CAPTURETHREAD_H
