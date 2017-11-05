#ifndef RAW_H
#define RAW_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <stdlib.h>

#define SADDR "127.0.0.1"

#define SPORT 6000
#define DPORT 6001

#define MSG "it works"

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

unsigned short csum(unsigned short *ptr,int nbytes);
#endif
