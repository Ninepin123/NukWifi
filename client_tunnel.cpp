#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <sstream>

#include "icmp_checksum.h"

// 定義 ICMP 封包資料區段的最大長度 (需扣除 ICMP 標頭 8 位元組)
// 我們使用 64 位元組的 ICMP 封包，所以 Payload 是 56 位元組。
#define ICMP_PACKET_SIZE 64 
#define PAYLOAD_SIZE (ICMP_PACKET_SIZE - 8)

using namespace std;

// 函數原型
void usage(const char *progname);

/**
 * @brief ICMP 隱蔽通道客戶端。
 * * 從標準輸入讀取資料，並將其分割後透過 ICMP Echo Request 的 Payload 傳輸。
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int sock;
    struct sockaddr_in dest_addr;
    char packet[ICMP_PACKET_SIZE];
    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;

    // 1. 建立 Raw Socket，需要 root 權限
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cerr << "錯誤: 建立 Raw Socket 失敗。請以 root 權限執行 (sudo)." << endl;
        return 1;
    }

    // 2. 設定目標位址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_ip, &dest_addr.sin_addr) <= 0) {
        cerr << "錯誤: 無效的目標 IP 位址" << endl;
        close(sock);
        return 1;
    }

    cout << "--- ICMP 隱蔽通道客戶端啟動 ---" << endl;
    cout << "目標: " << target_ip << endl;
    cout << "輸入欲傳輸的指令 (按 Ctrl+D 結束):" << endl;

    string line;
    uint16_t sequence = 0; // 用於封包排序和識別

    // 3. 讀取輸入並發送
    while (getline(cin, line)) {
        if (line.empty()) continue;

        // 將整行資料分割成 PAYLOAD_SIZE 大小的區塊
        for (size_t i = 0; i < line.length(); i += PAYLOAD_SIZE) {
            string chunk = line.substr(i, PAYLOAD_SIZE);
            size_t chunk_len = chunk.length();
            
            // 清空封包緩衝區並初始化 ICMP 標頭
            memset(packet, 0, ICMP_PACKET_SIZE);
            icmp_hdr->type = ICMP_ECHO;         // Echo Request
            icmp_hdr->code = 0;
            icmp_hdr->un.echo.id = htons(getpid()); // 使用 PID 作為 ID
            icmp_hdr->un.echo.sequence = htons(sequence++);

            // 複製資料到 Payload 區段
            char *payload = (char *)(packet + 8);
            memcpy(payload, chunk.c_str(), chunk_len);

            // 填充剩餘空間 (可選，但有助於檢測端分析固定長度)
            if (chunk_len < PAYLOAD_SIZE) {
                memset(payload + chunk_len, 0x20, PAYLOAD_SIZE - chunk_len); // 填充空格
            }

            // 計算並設定 Checksum (在設定完所有資料後計算)
            icmp_hdr->checksum = 0;
            icmp_hdr->checksum = in_cksum((uint16_t *)icmp_hdr, ICMP_PACKET_SIZE);

            // 發送封包
            if (sendto(sock, packet, ICMP_PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
                perror("sendto 失敗");
            } else {
                cout << "-> 發送分段 " << (ntohs(icmp_hdr->un.echo.sequence) & 0xFFFF) << " (" << chunk_len << " bytes): " << chunk << endl;
            }
            usleep(10000); // 10ms 延遲，避免流量過快
        }
    }

    cout << "--- 客戶端結束 ---" << endl;
    close(sock);
    return 0;
}

void usage(const char *progname) {
    cerr << "用法: " << progname << " <目標伺服器 IP>" << endl;
    cerr << "範例: sudo " << progname << " 192.168.1.10" << endl;
}