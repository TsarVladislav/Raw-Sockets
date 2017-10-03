/*
 * client.c - клиент, который отправляет сырой(raw) пакет без
 * заполнения IP заголовка
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <stdlib.h>

#define SADDR "127.0.0.1"

#define SPORT 5000
#define DPORT 5001

#define MSG "should work"

/* "Если UDP работает над IPv4, контрольная сумма вычисляется при помощи
 * псевдозаголовка, который содержит некоторую информацию из заголовка IPv4.
 * Псевдозаголовок не является настоящим IPv4-заголовком,
 * используемым для отправления IP-пакета."
 * https://ru.wikipedia.org/wiki/UDP#.D0.9F.D1.81.D0.B5.D0.B2.D0.B4.D0.BE.D0.B7.D0.B0.D0.B3.D0.BE.D0.BB.D0.BE.D0.B2.D0.BA.D0.B8
 */
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};
 
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
int main(int argc, const char *argv[])
{
    char datagram[4096];
    char source_ip[32];
    char *data, *pseudogram;
    int sock;
    int psize;
    struct pseudo_header psh;
    struct sockaddr_in sin;
    struct udphdr *udph;

    /* делаю сокет */
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sock == -1) {
        perror("error while creating a socket");
        return 1;
    }

    udph = (struct udphdr*) datagram;
    data = datagram +  sizeof(struct udphdr);
    /* Wireshark ругатеся на длину сообщение от 1 до 4
     * Malformed Packet. Не понятно почему, на 0 или на 11 оно не ругается
     */

    strcpy(data, MSG);

    /* адреса */
    strcpy(source_ip, SADDR);

    sin.sin_family = AF_INET;
    /* Note that the raw IPv4 protocol as such has no concept of a port,
     * they are only implemented by higher protocols like tcp(7) and udp(7).
     */
    sin.sin_port = 0;
    sin.sin_addr.s_addr = inet_addr(SADDR);

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


    if (sendto(sock, datagram, sizeof(struct udphdr) + strlen(data), 0,
              (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("Sendto fail");
    } else {
        printf("Packet sent!\n");
    }
    return 0;
}
