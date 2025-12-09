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
#include <cmath>
#include <map>

#include "icmp_checksum.h"

#define BUFFER_SIZE 1500
#define ENTROPY_THRESHOLD_HIGH 6.5 
#define ENTROPY_THRESHOLD_LOW  1.0 

using namespace std;

// 函數原型
void usage(const char *progname);
void process_icmp_packet(char *buffer, int len, int sock);
double calculate_entropy(const char *data, int len);
void send_echo_reply(int sock, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, char *data, int data_len);

int main(int argc, char *argv[]) {
    int sock;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // 建立 Raw Socket
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cerr << "錯誤: 建立 Raw Socket 失敗。請以 root 權限執行 (sudo)." << endl;
        return 1;
    }

    cout << "--- ICMP 隱蔽通道伺服器 (主動防禦模式) ---" << endl;
    cout << "提示: 請確保已執行 'sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1'" << endl;
    cout << "正在監聽 ICMP 封包..." << endl;

    while (true) {
        struct sockaddr_in from_addr;
        socklen_t addr_len = sizeof(from_addr);
        
        if ((bytes_read = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&from_addr, &addr_len)) < 0) {
            perror("recvfrom 失敗");
            continue;
        }

        process_icmp_packet(buffer, bytes_read, sock);
    }

    close(sock);
    return 0;
}

double calculate_entropy(const char *data, int len) {
    if (len <= 0) return 0.0;
    map<unsigned char, int> freq_map;
    for (int i = 0; i < len; ++i) freq_map[(unsigned char)data[i]]++;
    double entropy = 0.0;
    for (auto const& [key, val] : freq_map) {
        double probability = (double)val / len;
        entropy -= probability * log2(probability);
    }
    return entropy;
}

/**
 * [新增] 手動組建並發送 Echo Reply
 */
void send_echo_reply(int sock, struct iphdr *recv_ip_hdr, struct icmphdr *recv_icmp_hdr, char *data, int data_len) {
    char packet[BUFFER_SIZE];
    struct sockaddr_in dest_addr;
    
    // 1. 準備目標位址 (來源變目標)
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = recv_ip_hdr->saddr;

    // 2. 組建 ICMP 標頭
    struct icmphdr *reply_hdr = (struct icmphdr *)packet;
    reply_hdr->type = ICMP_ECHOREPLY; // Type 0
    reply_hdr->code = 0;
    reply_hdr->un.echo.id = recv_icmp_hdr->un.echo.id;       // 保持原 ID
    reply_hdr->un.echo.sequence = recv_icmp_hdr->un.echo.sequence; // 保持原 Seq
    reply_hdr->checksum = 0;

    // 3. 填入 Payload
    if (data_len > 0) {
        memcpy(packet + sizeof(struct icmphdr), data, data_len);
    }

    // 4. 計算 Checksum
    int packet_size = sizeof(struct icmphdr) + data_len;
    reply_hdr->checksum = in_cksum((uint16_t *)reply_hdr, packet_size);

    // 5. 發送
    sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

void process_icmp_packet(char *buffer, int len, int sock) {
    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    int ip_hdr_len = ip_hdr->ihl * 4;
    
    if (ip_hdr->protocol != IPPROTO_ICMP) return;

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_hdr_len);
    int icmp_len = len - ip_hdr_len;

    if (icmp_len < (int)sizeof(struct icmphdr)) return;

    if (icmp_hdr->type == ICMP_ECHO) { // 收到 Request
        char *payload = buffer + ip_hdr_len + sizeof(struct icmphdr);
        int payload_len = icmp_len - sizeof(struct icmphdr);
        
        if (payload_len <= 0) return;

        // --- 防禦檢測 ---
        double entropy = calculate_entropy(payload, payload_len);
        bool is_bad_packet = false;
        string reason = "";

        if (entropy > ENTROPY_THRESHOLD_HIGH) {
            is_bad_packet = true; 
            reason = "熵值過高";
        } else if (entropy < ENTROPY_THRESHOLD_LOW && payload_len > 16) {
            is_bad_packet = true; 
            reason = "熵值過低";
        }

        // [攔截點] 如果是壞封包，直接 return，不執行也不回覆！
        if (is_bad_packet) {
            cout << ">>> [BLOCK] " << inet_ntoa(*(struct in_addr *)&ip_hdr->saddr)
                 << " | Reason: " << reason << " (E: " << entropy << ")" << endl;
            return; 
        }

        // --- 通過檢測，正常處理 ---
        string command(payload, payload_len);
        // 清理空白字符
        size_t first = command.find_first_not_of(" \t\n\r");
        if (first != string::npos) {
            size_t last = command.find_last_not_of(" \t\n\r");
            command = command.substr(first, last - first + 1);
        } else command = "";

        cout << "[" << inet_ntoa(*(struct in_addr *)&ip_hdr->saddr) 
             << "] [PASS] Data: " << command << endl;

        // [手動回覆] 因為我們關了 Kernel Reply，現在要自己回
        send_echo_reply(sock, ip_hdr, icmp_hdr, payload, payload_len);
    }
}