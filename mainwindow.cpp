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
        connect(t, SIGNAL(captured(QString, QString)), this, SLOT(captured(QString, QString)));
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

void MainWindow::captured(QString packet, QString header){
    ui->listWidget->addItem(header);
    if(!ui->listWidget->item(ui->listWidget->count()-1)->text().contains(ui->lineEdit->text()))
    {
        ui->listWidget->item(ui->listWidget->count()-1)->setHidden(true);
    }
    packets.append(packet);
}

void MainWindow::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{
    int i = ui->listWidget->currentRow();
    QMessageBox msgBox;
    msgBox.setWindowTitle(item->text());
    msgBox.setText(packets.at(i));
    msgBox.exec();
}

void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    for(int row(0); row < ui->listWidget->count(); row++ )
        ui->listWidget->item(row)->setHidden(true);
    QList<QListWidgetItem*> matches ( ui->listWidget->findItems(arg1, Qt::MatchFlag::MatchContains) );
    for(QListWidgetItem* item : matches)
        item->setHidden(false);

}

void MainWindow::on_pushButton_2_clicked()
{
    ui->listWidget->clear();
    packets.clear();
}
