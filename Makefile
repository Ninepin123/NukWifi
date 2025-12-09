# GNU Make file for ICMP Covert Channel Project

# 編譯器和編譯旗標
CXX = g++
CXXFLAGS = -Wall -std=c++17 -O2

# 所有目標程式
TARGETS = client_tunnel server_tunnel detector

# 預設目標：編譯所有程式
all: $(TARGETS)

# 客戶端編譯規則
client_tunnel: client_tunnel.cpp icmp_checksum.h
	$(CXX) $(CXXFLAGS) -o $@ $<

# 伺服器端編譯規則
server_tunnel: server_tunnel.cpp icmp_checksum.h
	$(CXX) $(CXXFLAGS) -o $@ $<

# 檢測端編譯規則
detector: detector.cpp icmp_checksum.h
	$(CXX) $(CXXFLAGS) -o $@ $< -lm # -lm 連結 math 庫 (for log2)

# 清理編譯產物
clean:
	rm -f $(TARGETS)

.PHONY: all clean