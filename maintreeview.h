#ifndef MAINTREEVIEW_H
#define MAINTREEVIEW_H

#include <QMainWindow>
#include "sniffer.h"
namespace Ui {
class MainTreeView;
}

class MainTreeView : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainTreeView(QWidget *parent = 0);
    ~MainTreeView();

private slots:

private:
    Ui::MainTreeView *ui;
    Sniffer sniffer;
};

#endif // MAINTREEVIEW_H
