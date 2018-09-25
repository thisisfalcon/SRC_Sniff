#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <pcap.h>

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
        pcap_t *handle = pcap_open_live(ui->comboBox->currentText().toLatin1().data(), BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            QMessageBox msgBox;
            msgBox.setWindowTitle("Error");
            msgBox.setText("Interface \"" + ui->comboBox->currentText() + "\" could not be read.");
            msgBox.exec();
        }else{
            ui->comboBox->setEnabled(false);
            ui->pushButton->setText("Stop");
            struct pcap_pkthdr header;	/* The header that pcap gives us */
            const u_char *packet;
            /* Grab a packet */
            for(int i = 0; i < 10 ; i++){
                packet = pcap_next(handle, &header);
                ui->textBrowser->append("caught a packet");
            }
        }
    }else{
        ui->pushButton->setText("Listen");
        ui->comboBox->setEnabled(true);
    }

}

