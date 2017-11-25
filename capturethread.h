#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread(QObject *parent = 0)
        : QThread(parent)
    {
    }
protected:
    void run();

};

#endif // CAPTURETHREAD_H
