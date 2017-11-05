 /*
 * client.c - клиент, который отправляет сырой(raw) пакет с заполнением 
 * IP заголовка
 */
#include  "raw.h"

int main(int argc, const char *argv[])
{
    char datagram[4096];
    char source_ip[32];
    char *data, *pseudogram;
    int sock;
    int psize;
	int one;

    struct pseudo_header psh;
    struct sockaddr_in sin;
    struct udphdr *udph;
	struct iphdr *iph;

    /* делаю сокет */
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sock == -1) {
        perror("error while creating a socket");
        return 1;
    }

	iph = (struct iphdr *) datagram;
    udph = (struct udphdr*) (datagram + sizeof (struct iphdr));
    data = datagram +  sizeof(struct iphdr) + sizeof(struct udphdr);
    /* Wireshark ругатеся на длину сообщение от 1 до 4
     * Malformed Packet. Не понятно почему, на 0 или на 11 оно не ругается
     *
     * Я нашел:
     * Yeah Wireshark makes an assumption that UDP port 5000 could be TAPA
     * (Trapeze Access Point Access Protocol) and hence dissects it using
     * TAPA dissectors. From the wireshark TAPA code
     *  #define PORT_TAPA 5000
     *
     *  http://thread.gmane.org/gmane.network.simulator.ns3.user/4246
     */

    strcpy(data, MSG);

    sin.sin_family = AF_INET;
    /* Note that the raw IPv4 protocol as such has no concept of a port,
     * they are only implemented by higher protocols like tcp(7) and udp(7).
     */
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(SADDR);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof(struct udphdr) + strlen(data);
    iph->id = htonl (11111);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr (SADDR);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    /* UDP заголовок */
    udph->source = htons(SPORT);
    udph->dest = htons(DPORT);
    /* 8 байт служебной инфы заголовка + данные */
    udph->len = htons(8 + strlen(data));
    udph->check = 0;

    /* псевдозаголовок для подсчета контрольной суммы  */
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    psize = sizeof(struct pseudo_header) + sizeof(struct udphdr)
                           + strlen(data);

    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph,
           sizeof(struct udphdr) + strlen(data));

    /* контрольная сумма для udp заголовка */
    udph->check = csum((unsigned short *) pseudogram, psize);



    one = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0){
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    if (sendto(sock, datagram, iph->tot_len , 0,
               (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("sendto fail");
    } else {
        printf("sent!\n");
    }
    return 0;
}

/*
 * Контрольная сумма. RFC 1071. Честно украл(как, впрочем и почти весь код)
 * отсюда: http://www.binarytides.com/raw-udp-sockets-c-linux/
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((unsigned char*)&oddbyte)=*(unsigned char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    return(answer);
}
