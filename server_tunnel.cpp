#include <iostream>
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

#include "icmp_checksum.h"

// 最大封包緩衝區大小 (IP 標頭 + ICMP 標頭 + 資料)
#define BUFFER_SIZE 1500

using namespace std;

// 函數原型
void usage(const char *progname);
void process_icmp_packet(char *buffer, int len, int sock);

/**
 * @brief ICMP 隱蔽通道伺服器。
 * * 監聽所有 ICMP 封包，接收 Echo Request，解析其 Payload。
 */
int main(int argc, char *argv[]) {
    int sock;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // 1. 建立 Raw Socket，需要 root 權限
    // 設置 IPPROTO_ICMP 表示 Raw Socket 會接收到包含 IP 標頭的 ICMP 封包
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cerr << "錯誤: 建立 Raw Socket 失敗。請以 root 權限執行 (sudo)." << endl;
        return 1;
    }

    cout << "--- ICMP 隱蔽通道伺服器啟動 ---" << endl;
    cout << "正在監聽 ICMP 封包... (Ctrl+C 停止)" << endl;

    // 2. 持續接收封包
    while (true) {
        struct sockaddr_in from_addr;
        socklen_t addr_len = sizeof(from_addr);
        
        // 接收封包
        if ((bytes_read = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&from_addr, &addr_len)) < 0) {
            perror("recvfrom 失敗");
            continue;
        }

        process_icmp_packet(buffer, bytes_read, sock);
    }

    close(sock);
    return 0;
}

/**
 * @brief 處理接收到的 ICMP 封包。
 * * 解析 IP 和 ICMP 標頭，過濾出 Echo Request，提取 Payload。
 */
void process_icmp_packet(char *buffer, int len, int sock) {
    // 1. 解析 IP 標頭
    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    int ip_hdr_len = ip_hdr->ihl * 4; // IP 標頭長度 (位元組)
    
    // 檢查封包是否為 ICMP 協定
    if (ip_hdr->protocol != IPPROTO_ICMP) {
        return;
    }

    // 2. 解析 ICMP 標頭
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_hdr_len);
    int icmp_len = len - ip_hdr_len;

    // 檢查 ICMP 封包長度是否正確
    if (icmp_len < (int)sizeof(struct icmphdr)) {
        return;
    }

    // 3. 過濾 Echo Request (Type 8)
    if (icmp_hdr->type == ICMP_ECHO) {
        // 檢查 Checksum (可選，但推薦)
        uint16_t received_checksum = icmp_hdr->checksum;
        icmp_hdr->checksum = 0; // 計算前 Checksum 須設為 0
        uint16_t calculated_checksum = in_cksum((uint16_t *)icmp_hdr, icmp_len);
        icmp_hdr->checksum = received_checksum; // 恢復 Checksum

        if (received_checksum != calculated_checksum) {
            // cout << "警告: ICMP Checksum 錯誤" << endl;
            // return;
        }

        // 4. 提取 Payload
        char *payload = buffer + ip_hdr_len + sizeof(struct icmphdr);
        int payload_len = icmp_len - sizeof(struct icmphdr);
        
        // 為了安全性，只處理固定長度的 Payload (與客戶端發送的 PAYLOAD_SIZE 匹配)
        if (payload_len <= 0) return;

        // 將 Payload 視為指令或資料
        string command(payload, payload_len);
        size_t first_space = command.find_first_not_of(" \t\n\r"); // 移除開頭空白
        size_t last_space = command.find_last_not_of(" \t\n\r");   // 移除結尾空白
        if (first_space != string::npos && last_space != string::npos) {
            command = command.substr(first_space, last_space - first_space + 1);
        } else {
            command = "";
        }
        
        struct in_addr src_ip_addr;
        src_ip_addr.s_addr = ip_hdr->saddr;

        cout << "[" << inet_ntoa(src_ip_addr) 
             << "] Seq=" << ntohs(icmp_hdr->un.echo.sequence)
             << " Data(" << payload_len << " bytes): " 
             << command << endl;

        // 實際應用中，會在這裡執行命令或處理資料
        // 例如：system(command.c_str());
        
        // **可選: 回應 Echo Reply (Type 0)**
        // 如果需要完整的雙向通道，伺服器應該回覆 Echo Reply
        // 這裡暫時省略回覆，專注於接收資料。
    }
}