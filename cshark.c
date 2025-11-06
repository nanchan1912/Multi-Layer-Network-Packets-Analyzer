#include "cshark.h"
#include "packet_parser.h"
#include <signal.h>
#include <unistd.h>



// Global variables
session_t current_session = {0};
volatile sig_atomic_t stop_capture = 0;
int packet_counter = 0;
int current_datalink_type = 0;
pcap_t *global_handle = NULL;

// Signal handler for Ctrl+C
void sigint_handler(int sig) {
    (void)sig;
    stop_capture = 1;
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

// Clear session and free memory
void clear_session(void) {
    for (int i = 0; i < current_session.count; i++) {
        free(current_session.packets[i].data);
    }
    current_session.count = 0;
}

// Store packet in session
void store_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (current_session.count >= MAX_PACKETS) {
        return; // Session full
    }
    
    stored_packet_t *pkt = &current_session.packets[current_session.count];
    pkt->header = *header;
    pkt->data = (u_char *)malloc(header->caplen);
    if (pkt->data) {
        memcpy(pkt->data, packet, header->caplen);
        pkt->id = current_session.count + 1;
        current_session.count++;
    }
}

// Packet handler callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    
    packet_counter++;
    parse_and_display_packet(header, packet, packet_counter, 0, current_datalink_type);
    store_packet(header, packet);
}

// Display available interfaces
int display_interfaces(pcap_if_t **alldevs) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("\n[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... ");
    
    if (pcap_findalldevs(alldevs, errbuf) == -1) {
        printf("Failed!\n");
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    printf("Found!\n\n");
    
    int i = 1;
    for (pcap_if_t *d = *alldevs; d != NULL; d = d->next) {
        printf("%d. %s", i++, d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }
    
    return i - 1;
}

// Select interface
pcap_if_t* select_interface(pcap_if_t *alldevs, int count) {
    int choice;
    printf("\nSelect an interface to sniff (1-%d): ", count);
    
    int scan_result = scanf("%d", &choice);
    
    // Check for EOF (Ctrl+D)
    if (scan_result == EOF) {
        printf("\n[C-Shark] EOF detected. Exiting cleanly.\n");
        exit(0);
    }
    
    if (scan_result != 1 || choice < 1 || choice > count) {
        printf("Invalid selection.\n");
        return NULL;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    pcap_if_t *selected = alldevs;
    for (int i = 1; i < choice; i++) {
        selected = selected->next;
    }
    
    return selected;
}

// Display main menu
int display_main_menu(const char *interface_name) {
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", interface_name);
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n");
    printf("\nChoice: ");
    
    int choice;
    int scan_result = scanf("%d", &choice);
    
    // Check for EOF (Ctrl+D)
    if (scan_result == EOF) {
        printf("\n\n[C-Shark] EOF detected. Shutting down. Stay sharp! 🦈\n");
        clear_session();
        exit(0);
    }
    
    if (scan_result != 1) {
        // Clear input buffer
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return -1;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    return choice;
}

// Start sniffing without filter
void start_sniffing_all(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Clear previous session
    clear_session();
    packet_counter = 0;
    stop_capture = 0;
    
    printf("\n[C-Shark] Opening interface '%s' for capture...\n", device);
    
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return;
    }
    
    // Get the datalink type for this interface
    current_datalink_type = pcap_datalink(handle);
    
    global_handle = handle;
    
    printf("[C-Shark] Starting packet capture. Press Ctrl+C to stop.\n\n");
    
    // Set up signal handler
    signal(SIGINT, sigint_handler);
    
    // Start capture loop
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_close(handle);
    global_handle = NULL;
    
    printf("\n[C-Shark] Capture stopped. Captured %d packets.\n", packet_counter);
}

// Start sniffing with filter
void start_sniffing_filtered(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[MAX_FILTER_LEN];
    
    printf("\n[C-Shark] Available filters:\n");
    printf("1. HTTP\n");
    printf("2. HTTPS\n");
    printf("3. DNS\n");
    printf("4. ARP\n");
    printf("5. TCP\n");
    printf("6. UDP\n");
    printf("\nSelect filter (1-6): ");
    
    int choice;
    int scan_result = scanf("%d", &choice);
    
    // Check for EOF (Ctrl+D)
    if (scan_result == EOF) {
        printf("\n[C-Shark] EOF detected. Returning to menu.\n");
        return;
    }
    
    if (scan_result != 1 || choice < 1 || choice > 6) {
        printf("Invalid filter selection.\n");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    // Build filter expression
    switch (choice) {
        case 1: strcpy(filter_exp, "tcp port 80"); break;
        case 2: strcpy(filter_exp, "tcp port 443"); break;
        case 3: strcpy(filter_exp, "udp port 53"); break;
        case 4: strcpy(filter_exp, "arp"); break;
        case 5: strcpy(filter_exp, "tcp"); break;
        case 6: strcpy(filter_exp, "udp"); break;
        default: strcpy(filter_exp, ""); break;
    }
    
    // Clear previous session
    clear_session();
    packet_counter = 0;
    stop_capture = 0;
    
    printf("\n[C-Shark] Opening interface '%s' with filter '%s'...\n", device, filter_exp);
    
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return;
    }
    
    // Get the datalink type for this interface
    current_datalink_type = pcap_datalink(handle);
    
    // Compile and apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }
    
    global_handle = handle;
    
    printf("[C-Shark] Starting filtered packet capture. Press Ctrl+C to stop.\n\n");
    
    // Set up signal handler
    signal(SIGINT, sigint_handler);
    
    // Start capture loop
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
    global_handle = NULL;
    
    printf("\n[C-Shark] Capture stopped. Captured %d packets.\n", packet_counter);
}

// Inspect last session
void inspect_last_session(void) {
    if (current_session.count == 0) {
        printf("\n[C-Shark] No packets in last session. Capture some packets first!\n");
        return;
    }
    
    printf("\n[C-Shark] Last Session Summary - %d packets captured:\n", current_session.count);
    printf("==============================================\n");
    
    // Display summary of all packets
    for (int i = 0; i < current_session.count && i < 50; i++) {
        stored_packet_t *pkt = &current_session.packets[i];
        printf("ID: %d | Time: %ld.%06ld | Length: %d bytes\n",
               pkt->id, pkt->header.ts.tv_sec, pkt->header.ts.tv_usec, pkt->header.len);
    }
    
    if (current_session.count > 50) {
        printf("... and %d more packets\n", current_session.count - 50);
    }
    
    printf("\nEnter Packet ID to inspect in detail (0 to return): ");
    int id;
    int scan_result = scanf("%d", &id);
    
    // Check for EOF (Ctrl+D)
    if (scan_result == EOF) {
        printf("\n[C-Shark] EOF detected. Returning to menu.\n");
        return;
    }
    
    if (scan_result != 1) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    if (id == 0) return;
    
    if (id < 1 || id > current_session.count) {
        printf("Invalid packet ID.\n");
        return;
    }
    
    // Display detailed packet analysis
    stored_packet_t *pkt = &current_session.packets[id - 1];
    printf("\n========== DETAILED PACKET INSPECTION ==========\n");
    parse_and_display_packet(&pkt->header, pkt->data, pkt->id, 1, current_datalink_type);
}

// Main function
int main(void) {
    pcap_if_t *alldevs = NULL;
    pcap_if_t *selected_device = NULL;
    int device_count;
    
    // Display interfaces
    device_count = display_interfaces(&alldevs);
    if (device_count <= 0) {
        return 1;
    }
    
    // Select interface
    selected_device = select_interface(alldevs, device_count);
    if (selected_device == NULL) {
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    char device_name[256];
    strncpy(device_name, selected_device->name, sizeof(device_name) - 1);
    device_name[sizeof(device_name) - 1] = '\0';
    
    // Free device list (we've saved the name)
    pcap_freealldevs(alldevs);
    
    // Main menu loop
    while (1) {
        int choice = display_main_menu(device_name);
        
        switch (choice) {
            case 1:
                start_sniffing_all(device_name);
                break;
            case 2:
                start_sniffing_filtered(device_name);
                break;
            case 3:
                inspect_last_session();
                break;
            case 4:
                printf("\n[C-Shark] Shutting down. Stay sharp! 🦈\n");
                clear_session();
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }
    
    return 0;
}
