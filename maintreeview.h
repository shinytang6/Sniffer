#ifndef MAINTREEVIEW_H
#define MAINTREEVIEW_H

#include <QMainWindow>
#include "sniffer.h"
#include <QTreeView>
#include <QStandardItemModel>

class MainTreeView :public QTreeView
{
    Q_OBJECT

public:
    MainTreeView(QTreeView *treeView);
    ~MainTreeView();

    QStandardItemModel *mainModel;
    void addOneCaptureItem();

private slots:

private:
    Sniffer sniffer;
};

#endif // MAINTREEVIEW_H
