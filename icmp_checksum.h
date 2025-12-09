#ifndef ICMP_CHECKSUM_H
#define ICMP_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/**
 * @brief 計算 ICMP 封包的總和檢查碼 (Checksum)。
 * * 總和檢查碼的計算方式是將每個 16 位元組 (word) 的資料加總，
 * 溢位會迴繞相加，最後取反 (bitwise NOT)。
 * * @param addr 指向 ICMP 封包的起始位址。
 * @param len ICMP 封包的長度 (位元組)。
 * @return uint16_t 計算出的總和檢查碼。
 */
uint16_t in_cksum(uint16_t *addr, int len) {
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    // 將資料以 16-bit 為單位相加
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    // 處理剩餘的單一位元組 (如果有)
    if (nleft == 1) {
        *(uint8_t *)(&answer) = *(uint8_t *)w;
        sum += answer;
    }

    // 將 32-bit 的 sum 進行高位和低位的迴繞相加
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); // 再次加上迴繞後的溢位

    // 取反得到檢查碼
    answer = (uint16_t)~sum;
    return answer;
}

#endif // ICMP_CHECKSUM_H