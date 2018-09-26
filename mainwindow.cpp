#include "mainwindow.h"
#include "ui_mainwindow.h"

char errbuf[PCAP_ERRBUF_SIZE+1];

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    pcap_if *alldevs;
    pcap_if_t *d;
    if (pcap_findalldevs(&alldevs,errbuf)!=-1)
    {
        QStringList retval;
        for(d=alldevs;d;d=d->next)
        {
            ui->comboBox->addItem(QString(d->name));
        }
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    if(ui->pushButton->text() == "Listen"){
        t = new Thread(ui->comboBox->currentText());
        ui->comboBox->setEnabled(false);
        ui->pushButton->setText("Stop");
        connect(t, SIGNAL(captured(QString)), this, SLOT(captured(QString)));
        connect(t, SIGNAL(error(QString)), this, SLOT(error(QString)));
        t->start();
    }else{
        ui->pushButton->setText("Listen");
        ui->comboBox->setEnabled(true);
        t->terminate();
    }

}

void MainWindow::error(QString message){
    QMessageBox msgBox;
    msgBox.setWindowTitle("Error");
    msgBox.setText(message);
    msgBox.exec();
    ui->pushButton->setText("Listen");
    ui->comboBox->setEnabled(true);
    t->terminate();
}

void MainWindow::captured(QString packet){
    ui->textBrowser->append(packet);
}
