# C-Shark: Terminal Packet Sniffer
> i like whales more than sharks

This repo is a terminal CLI network packet analyzer built with libpcap. Captures and dissects packets layer-by-layer through Ethernet, IP, TCP/UDP, supports protocol filtering, stores session data, and provides detailed packet inspection with hex dumps.


Features
--------
- **Interface selection**: lists all available network interfaces, user selects one to monitor
- **Live packet capture**: displays real-time packet feed with ID, timestamp, length, and decoded headers
- **Layer-by-layer dissection**:
  - Layer 2 (Ethernet): source/dest MAC, EtherType (IPv4/IPv6/ARP)
  - Layer 3 (Network): IPv4/IPv6 headers (IPs, TTL, protocol, flags), ARP (operation, sender/target)
  - Layer 4 (Transport): TCP (ports, seq/ack, flags, window), UDP (ports, length)
  - Layer 7 (Application): protocol identification (HTTP/HTTPS/DNS), payload hex dump (first 64 bytes)
- **Protocol filtering**: capture only HTTP, HTTPS, DNS, ARP, TCP, or UDP traffic
- **Session storage**: stores last capture session (up to 10,000 packets), with memory cleanup between sessions
- **Detailed inspection**: select any packet from last session for full frame hex dump and comprehensive header analysis
- **Graceful controls**: Ctrl+C stops capture and returns to menu, Ctrl+D exits cleanly

Build and Run
-----
```bash
make
sudo ./cshark
```



Workflow:
1. Program scans and lists available interfaces (e.g., `wlan0`, `lo`, `any`)
2. You can select an interface by number
3. Main menu:
   - **Start Sniffing (All Packets)**: captures everything on selected interface
   - **Start Sniffing (With Filters)**: prompts for protocol filter (HTTP/HTTPS/DNS/ARP/TCP/UDP)
   - **Inspect Last Session**: lists packets from last capture, user selects packet ID for detailed view
   - **Exit C-Shark**: clean shutdown

Controls during capture:
- `Ctrl+C`: stop capture, return to main menu
- `Ctrl+D`: exit program immediately

Protocol and behavior summary
------------------------------
- **Packet capture**: uses `pcap_open_live()` to open interface, `pcap_loop()` with callback for packet processing
- **Protocol decoding**: parses headers sequentially (Ethernet → IP/ARP → TCP/UDP → payload). Uses standard structs from networking headers.
- **Port identification**: common ports decoded (80=HTTP, 443=HTTPS, 53=DNS). Others labeled with port number only.
- **Hex dump format**: displays bytes in 16-byte rows with corresponding ASCII representation (non-printable chars shown as `.`)
- **Filtering**: applies BPF (Berkeley Packet Filter) expressions via `pcap_compile()` and `pcap_setfilter()` for protocol-specific capture
- **Session management**: allocates array of packet structs on first capture, frees and reallocates on new session. Max capacity defined by `MAX_PACKETS` macro (default 10,000).
- **Signal handling**: custom SIGINT handler stops capture loop without terminating program

Notes:
- Requires root/sudo due to raw socket access


Cool GUy Tips:
-------------------------------
If you wanna test, run Wireshark side by side
```bash
# Terminal 1
sudo ./cshark

# Terminal 2
sudo wireshark
```
Compare packet counts, header values, and payload content to check we correct
> here is a list of my top few favorite sharks (no wireshark):
> great white | whale shark | hammerhead | lemon shark | nurse shark | tiger shark 
