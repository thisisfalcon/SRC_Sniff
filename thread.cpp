#include "thread.h"

char err[PCAP_ERRBUF_SIZE+1];

Thread::Thread(QString interface)
{
    this->interface=interface;
}

Thread::Thread()
{

}

void Thread::run()
{
    pcap_t *handle = pcap_open_live(interface.toLatin1().data(), BUFSIZ, 1, 1000, err);
    if (handle == NULL) {
        emit error("Interface \"" + interface + "\" could not be read.");
    }else{
        struct pcap_pkthdr header;
        const u_char *packet;
        /* Grab a packet */
        while(1){
            packet = pcap_next(handle, &header);
            emit captured("caught a packet");
        }
    }
}
