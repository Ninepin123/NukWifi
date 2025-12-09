#include <iostream>
#include <cstring>
#include <cmath>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <string>
#include <iomanip>
#include <map>
#include <algorithm> // for std::max

// 引入 icmp_checksum.h，需要確保它在同一個目錄中
#include "icmp_checksum.h"

#define BUFFER_SIZE 1500
// ICMP Payload 的 Shannon Entropy 理論最大值為 8 (即每個位元組的出現機率相等)
// 高於 6.5 通常被視為可疑，代表資料高度隨機化或經過加密/編碼。
#define ENTROPY_THRESHOLD 6.5 

using namespace std;

// 函數原型
double calculate_entropy(const char *data, int len);
void detect_icmp_traffic(char *buffer, int len);

/**
 * @brief 計算給定資料區塊的 Shannon 熵。
 * * H = -Σ p_i * log2(p_i)
 * @param data 資料緩衝區。
 * @param len 資料長度。
 * @return double 熵值 (0 到 8)。
 */
double calculate_entropy(const char *data, int len) {
    if (len <= 0) return 0.0;

    map<unsigned char, int> freq_map;
    // 計算每個位元組的頻率
    for (int i = 0; i < len; ++i) {
        freq_map[(unsigned char)data[i]]++;
    }

    double entropy = 0.0;
    
    // 使用 C++11 兼容的 for 迴圈遍歷 map
    for (map<unsigned char, int>::const_iterator it = freq_map.begin(); it != freq_map.end(); ++it) {
        int val = it->second; // 這是該位元組的出現次數
        double probability = (double)val / len;
        
        // 熵的計算公式: -p * log2(p)
        // 使用 log2(x) = log(x) / log(2)
        entropy -= probability * log2(probability);
    }

    return entropy;
}

/**
 * @brief 深度檢測 ICMP 封包，特別是分析 Payload 熵值。
 * * 由於 Raw Socket 現已設為 IPPROTO_ICMP，我們接收到的緩衝區 (buffer)
 * * 會包含 IP 標頭 (ihl * 4) + ICMP 標頭 + ICMP Payload。
 */
void detect_icmp_traffic(char *buffer, int len) {
    // 1. 解析 IP 標頭
    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    int ip_hdr_len = ip_hdr->ihl * 4; // IP 標頭長度 (位元組)

    if (ip_hdr->protocol != IPPROTO_ICMP) {
        // 理論上，如果 socket 設定為 IPPROTO_ICMP，核心應該只傳遞 ICMP 封包給我們
        return;
    }

    // 2. 解析 ICMP 標頭
    // ICMP 標頭緊接在 IP 標頭之後
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_hdr_len);
    int icmp_len = len - ip_hdr_len; // 整個 ICMP 封包的長度

    if (icmp_len < (int)sizeof(struct icmphdr)) {
        return;
    }

    struct in_addr src_ip_addr;
    src_ip_addr.s_addr = ip_hdr->saddr;
    struct in_addr dst_ip_addr;
    dst_ip_addr.s_addr = ip_hdr->daddr;
    
    // 格式化輸出基礎資訊
    cout << "\n[ICMP 流量] " << inet_ntoa(src_ip_addr) 
         << " -> " << inet_ntoa(dst_ip_addr) 
         << " Type: " << (int)icmp_hdr->type;

    // 只對 Echo Request (8) 和 Reply (0) 進行深度檢測
    if (icmp_hdr->type == ICMP_ECHO || icmp_hdr->type == ICMP_ECHOREPLY) {
        // 3. 提取 Payload
        // Payload 緊接在 ICMP 標頭之後
        char *payload = buffer + ip_hdr_len + sizeof(struct icmphdr);
        int payload_len = icmp_len - sizeof(struct icmphdr);

        if (payload_len > 0) {
            // 4. 計算 Payload 熵值
            double entropy = calculate_entropy(payload, payload_len);
            
            cout << ", Payload Size: " << payload_len 
                 << " bytes, Entropy: " << fixed << setprecision(4) << entropy;

            // 5. 根據閾值進行判斷
            if (entropy > ENTROPY_THRESHOLD) {
                cout << " *** [惡意警報] 熵值過高 - 潛在隱蔽通道或加密流量 ***";
            } else if (entropy < 1.0 && payload_len > 8) { 
                 // 熵值極低（接近 0 或 1）且資料長度較長，通常意味著大量的填充或單一重複字元。
                 cout << " *** [低熵警報] 數據高度重複 - 可能為填充或非正常數據 ***";
            }
        }
    }
    cout << endl;
}

/**
 * @brief 檢測端主程式。
 * * 監聽所有 ICMP 流量。
 */
int main() {
    int sock;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // 1. 建立 Raw Socket，改為接收 ICMP 封包 (IPPROTO_ICMP)
    // 這樣可以避免在部分受限環境（如某些WSL配置）中因 IPPROTO_IP 權限過大而失敗。
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cerr << "錯誤: 建立 Raw Socket 失敗。請以 root 權限執行 (sudo)." << endl;
        return 1;
    }

    // 2. 由於我們使用 IPPROTO_ICMP，核心會替我們處理 IP 標頭，
    // 所以我們需要手動設定 IP_HDRINCL，確保接收到的緩衝區包含 IP 標頭。
    // 注意：這個選項的行為在不同系統和協議下可能略有不同，但通常 Raw Socket
    // 接收到的 ICMP 封包會帶有 IP 標頭。我們仍然嘗試設置。
    int on = 1;
    // 嘗試設定 IP_HDRINCL，告訴核心我們預期 IP 標頭也包含在內
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        // 如果設定失敗，不一定是致命錯誤，可能是核心行為所致，給出警告即可。
        // perror("警告: setsockopt(IP_HDRINCL) 可能失敗或不必要");
    }
    
    cout << "--- ICMP 深度檢測端啟動 (Entropy Threshold: " << ENTROPY_THRESHOLD << ") ---" << endl;
    cout << "正在監聽 ICMP 封包... (Ctrl+C 停止)" << endl;

    // 3. 持續接收封包
    while (true) {
        if ((bytes_read = recv(sock, buffer, BUFFER_SIZE, 0)) < 0) {
            perror("recv 失敗");
            continue;
        }

        detect_icmp_traffic(buffer, bytes_read);
    }

    close(sock);
    return 0;
}