#ifndef THREAD_H
#define THREAD_H
#include <QtCore>
#include <pcap.h>

class Thread : public QThread
{
    Q_OBJECT
public:
    Thread(QString interface);
    Thread();
    void run();
private:
    QString interface;
signals:
    void error(QString message);
    void captured(QString packet);
};
#endif // THREAD_H
