#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define BATCH_SIZE 64
#define DISCOVERY_PORT 25565
#define MAX_METADATA_THREADS 50
#define CONNECT_TIMEOUT_SEC 2
#define TARGET_PORT 12345

struct result_queue {
  char **ips;
  int capacity;
  int head;
  int tail;
  int count;
  pthread_mutex_t lock;
  pthread_cond_t not_empty;
  bool finished;
};

struct scan_range {
  uint32_t start_ip;
  uint32_t count;
};

struct target_queue {
  struct scan_range *ranges;
  int capacity;
  int count;
  int head;
};
struct target_queue targets;

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
  size_t size;
};

struct xdp_worker_config {
  int queue_id;
  const char *ifname;
  const char *start_ip_str;
  char source_ip_str[INET_ADDRSTRLEN];
  uint32_t num_ips;
  int start_port;
  int end_port;
  unsigned long pps_limit;
  unsigned char src_mac[6];
  unsigned char dest_mac[6];
  struct xsk_umem_info *umem;
  int shared_umem;
};

struct sniffer_config {
  char ifname[IFNAMSIZ];
  int start_port;
  int end_port;
};

struct ping_response {
  char version[64];
  char description[256];
  int online;
  int max;
  bool success;
};

static volatile int stop_signal = 0;
static struct result_queue results;
static uint64_t scanned_count = 0;
static uint64_t found_count = 0;
static char *output_file = NULL;
static int global_map_fd = -1;

static unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

static unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
  struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
  } psh;

  psh.source_address = iph->saddr;
  psh.dest_address = iph->daddr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr));

  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr));

  unsigned short res = checksum((unsigned short *)pseudogram, psize);
  free(pseudogram);
  return res;
}

void get_mac_address(const char *ifname, unsigned char *mac) {
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  ioctl(fd, SIOCGIFHWADDR, &ifr);
  memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
  close(fd);
}

void get_ip_address(const char *ifname, char *ip_str) {
  int fd;
  struct ifreq ifr;
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  strcpy(ip_str, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

uint32_t ip_to_int(const char *ip) {
  struct in_addr addr;
  char temp[64];
  strncpy(temp, ip, 63);
  temp[63] = '\0';

  char *slash = strchr(temp, '/');
  if (slash)
    *slash = '\0';

  if (inet_aton(temp, &addr) == 0) {
    fprintf(stderr, "Invalid IP: %s\n", ip);
    return 0;
  }
  return ntohl(addr.s_addr);
}

uint32_t parse_cidr_count(const char *cidr) {
  const char *slash = strchr(cidr, '/');
  if (!slash)
    return 1;
  int bits = atoi(slash + 1);
  if (bits < 0 || bits > 32)
    return 1;
  return 1 << (32 - bits);
}

void int_to_ip(uint32_t ip, char *buf) {
  struct in_addr addr;
  addr.s_addr = htonl(ip);
  strcpy(buf, inet_ntoa(addr));
}

void write_varint(int value, char **buf) {
  do {
    char temp = (char)(value & 0x7F);
    value >>= 7;
    if (value != 0)
      temp |= 0x80;
    **buf = temp;
    (*buf)++;
  } while (value != 0);
}

int read_varint(int sock, int *val) {
  int numRead = 0;
  int result = 0;
  char byte;
  while (1) {
    if (recv(sock, &byte, 1, 0) <= 0)
      return -1;
    int value = (byte & 0x7F);
    result |= (value << (7 * numRead));
    numRead++;
    if (numRead > 5)
      return -1;
    if ((byte & 0x80) == 0)
      break;
  }
  *val = result;
  return 0;
}

void extract_json_int(const char *json, const char *key, int *out) {
  char search[64];
  sprintf(search, "\"%s\":", key);
  char *pos = strstr(json, search);
  if (pos) {
    *out = atoi(pos + strlen(search));
  }
}

void extract_json_string(const char *json, const char *key, char *out,
                         int max_len) {
  char search[64];
  sprintf(search, "\"%s\":\"", key);
  char *pos = strstr(json, search);
  if (pos) {
    pos += strlen(search);
    char *end = strchr(pos, '"');
    if (end) {
      int len = end - pos;
      if (len > max_len - 1)
        len = max_len - 1;
      strncpy(out, pos, len);
      out[len] = '\0';
    }
  }
}

bool is_file(const char *path) {
  struct stat path_stat;
  if (stat(path, &path_stat) != 0)
    return false;
  return S_ISREG(path_stat.st_mode);
}

void load_targets(const char *input) {
  targets.capacity = 50000;
  targets.ranges = malloc(sizeof(struct scan_range) * targets.capacity);
  targets.count = 0;
  targets.head = 0;

  if (is_file(input)) {
    FILE *fp = fopen(input, "r");
    if (!fp) {
      perror("Failed to open target file");
      exit(1);
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
      line[strcspn(line, "\n")] = 0;
      if (strlen(line) < 7)
        continue;

      uint32_t count = parse_cidr_count(line);
      uint32_t ip = ip_to_int(line);
      if (ip != 0) {
        targets.ranges[targets.count].start_ip = ip;
        targets.ranges[targets.count].count = count;
        targets.count++;
      }
    }
    fclose(fp);
    printf("Loaded %d ranges from file %s\n", targets.count, input);
  } else {
    uint32_t count = parse_cidr_count(input);
    uint32_t ip = ip_to_int(input);
    targets.ranges[0].start_ip = ip;
    targets.ranges[0].count = count;
    targets.count = 1;
  }
}

void check_minecraft_server(const char *ip, int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return;

  struct timeval timeout;
  timeout.tv_sec = CONNECT_TIMEOUT_SEC;
  timeout.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = inet_addr(ip);

  if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    close(sock);
    return;
  }

  char buffer[1024];
  char *ptr = buffer;

  char data[512];
  char *dptr = data;

  write_varint(0x00, &dptr);
  write_varint(47, &dptr);
  write_varint(strlen(ip), &dptr);
  memcpy(dptr, ip, strlen(ip));
  dptr += strlen(ip);
  unsigned short p = port;
  *dptr++ = (p >> 8) & 0xFF;
  *dptr++ = p & 0xFF;
  write_varint(1, &dptr);

  int data_len = dptr - data;
  write_varint(data_len, &ptr);
  memcpy(ptr, data, data_len);
  ptr += data_len;

  data_len = 1;
  write_varint(data_len, &ptr);
  char pid = 0x00;
  *ptr++ = pid;

  send(sock, buffer, ptr - buffer, 0);

  int length;
  if (read_varint(sock, &length) != 0) {
    close(sock);
    return;
  }

  int packet_id;
  if (read_varint(sock, &packet_id) != 0) {
    close(sock);
    return;
  }

  if (packet_id == 0x00) {
    int json_len;
    if (read_varint(sock, &json_len) != 0) {
      close(sock);
      return;
    }

    char *json = malloc(json_len + 1);
    int total_read = 0;
    while (total_read < json_len) {
      int r = recv(sock, json + total_read, json_len - total_read, 0);
      if (r <= 0)
        break;
      total_read += r;
    }
    json[total_read] = '\0';

    char version[64] = "Unknown";
    char description[128] = "";
    int online = 0, max = 0;

    extract_json_string(json, "name", version, 64);
    extract_json_int(json, "online", &online);
    extract_json_int(json, "max", &max);

    char *desc_pos = strstr(json, "\"description\":");
    if (desc_pos) {
      desc_pos += 14;
      while (*desc_pos == ' ' || *desc_pos == '\r' || *desc_pos == '\n')
        desc_pos++;

      if (*desc_pos == '"') {
        desc_pos++;
        char *end = strchr(desc_pos, '"');
        if (end) {
          int len = end - desc_pos;
          if (len > 127)
            len = 127;
          strncpy(description, desc_pos, len);
          description[len] = '\0';
        }
      } else if (*desc_pos == '{') {
        char *text_pos = strstr(desc_pos, "\"text\":");
        if (text_pos && (text_pos - desc_pos) < 200) {
          text_pos += 7;
          while (*text_pos == ' ' || *text_pos == '"')
            text_pos++;
          char *end = strchr(text_pos, '"');
          if (end) {
            int len = end - text_pos;
            if (len > 127)
              len = 127;
            strncpy(description, text_pos, len);
            description[len] = '\0';
          }
        }
      }
    }

    printf("%s:%d -> (%s) - (%d/%d) - (%s)\n", ip, port, version, online, max,
           description);

    if (output_file) {
      FILE *fp = fopen(output_file, "a");
      if (fp) {
        fprintf(fp, "%s:%d -> (%s) - (%d/%d) - (%s)\n", ip, port, version,
                online, max, description);
        fclose(fp);
      }
    }

    found_count++;
    free(json);
  }
  close(sock);
}

void *metadata_worker_func(void *arg) {
  while (1) {
    char *ip = NULL;
    pthread_mutex_lock(&results.lock);
    while (results.count == 0 && !results.finished) {
      pthread_cond_wait(&results.not_empty, &results.lock);
    }
    if (results.count == 0 && results.finished) {
      pthread_mutex_unlock(&results.lock);
      break;
    }

    char *entry = results.ips[results.head];
    results.ips[results.head] = NULL;
    results.head = (results.head + 1) % results.capacity;
    results.count--;
    pthread_mutex_unlock(&results.lock);

    if (entry) {
      char ip[INET_ADDRSTRLEN] = {0};
      int port = 25565;

      char *colon = strchr(entry, ':');
      if (colon) {
        *colon = '\0';
        strncpy(ip, entry, sizeof(ip) - 1);
        port = atoi(colon + 1);
      } else {
        strncpy(ip, entry, sizeof(ip) - 1);
      }

      check_minecraft_server(ip, port);
      free(entry);
    }
  }
  return NULL;
}

void enqueue_ip(const char *ip_str) {
  pthread_mutex_lock(&results.lock);
  if (results.count < results.capacity) {
    results.ips[results.tail] = strdup(ip_str);
    results.tail = (results.tail + 1) % results.capacity;
    results.count++;
    pthread_cond_signal(&results.not_empty);
  }
  pthread_mutex_unlock(&results.lock);
}

static struct xsk_umem_info *configure_umem(void *buffer, uint64_t size) {
  struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
  int ret =
      xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
  if (ret)
    return NULL;
  umem->buffer = buffer;
  umem->size = size;
  return umem;
}

void *raw_socket_sniffer(void *arg) {
  struct sniffer_config *cfg = (struct sniffer_config *)arg;
  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_raw < 0) {
    perror("Socket Error");
    return NULL;
  }

  struct ifreq ifr;
  strncpy(ifr.ifr_name, cfg->ifname, IFNAMSIZ - 1);
  setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));

  unsigned char *buffer = (unsigned char *)malloc(65536);
  while (!stop_signal) {
    int data_size = recvfrom(sock_raw, buffer, 65536, 0, NULL, NULL);
    if (data_size < 0)
      continue;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    if (iph->protocol == IPPROTO_TCP) {
      unsigned short iphdrlen = iph->ihl * 4;
      struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iphdrlen);

      if (tcph->dest == htons(TARGET_PORT) && tcph->syn == 1 &&
          tcph->ack == 1) {
        int src_port = ntohs(tcph->source);

        struct in_addr source_ip;
        source_ip.s_addr = iph->saddr;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &source_ip, ip_str, INET_ADDRSTRLEN);

        static int debug_print_count = 0;
        if (debug_print_count < 10) {
          printf("DEBUG: SAW PACKET from %s:%d (Target Range: %d-%d)\n", ip_str,
                 src_port, cfg->start_port, cfg->end_port);
          debug_print_count++;
        }

        char ip_port_str[64];
        snprintf(ip_port_str, sizeof(ip_port_str), "%s:%d", ip_str, src_port);

        enqueue_ip(ip_port_str);
      }
    }
  }
  close(sock_raw);
  free(buffer);
  return NULL;
}

void *xdp_worker_func(void *arg) {
  struct xdp_worker_config *cfg = (struct xdp_worker_config *)arg;
  struct xsk_socket_info {
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    struct xsk_socket *xsk;
  } xsk_info;

  struct xsk_socket_config xsk_cfg;
  xsk_cfg.rx_size = NUM_FRAMES;
  xsk_cfg.tx_size = NUM_FRAMES;
  xsk_cfg.libbpf_flags = 1;
  xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
  xsk_cfg.bind_flags = cfg->shared_umem ? XDP_SHARED_UMEM : 0;

  if (xsk_socket__create(&xsk_info.xsk, cfg->ifname, cfg->queue_id,
                         cfg->umem->umem, &xsk_info.rx, &xsk_info.tx,
                         &xsk_cfg)) {
    perror("xsk_socket__create");
    return NULL;
  }

  int sock_fd = xsk_socket__fd(xsk_info.xsk);
  int ret = bpf_map_update_elem(global_map_fd, &cfg->queue_id, &sock_fd, 0);
  if (ret) {
  }

  int outstanding = 0;

  for (int t_idx = 0; t_idx < targets.count; t_idx++) {
    uint32_t current_ip_int = targets.ranges[t_idx].start_ip;
    uint32_t end_ip_int = current_ip_int + targets.ranges[t_idx].count;
    int current_port = cfg->start_port;

    uint32_t idx_p;

    time_t last_sec = time(NULL);
    unsigned long sent_this_sec = 0;

    while (!stop_signal && current_ip_int < end_ip_int) {
      uint32_t idx_cq;
      int n_completed =
          xsk_ring_cons__peek(&cfg->umem->cq, BATCH_SIZE, &idx_cq);
      if (n_completed > 0) {
        xsk_ring_cons__release(&cfg->umem->cq, n_completed);
      }

      if (cfg->pps_limit > 0) {
        time_t now = time(NULL);
        if (now != last_sec) {
          sent_this_sec = 0;
          last_sec = now;
        }
        if (sent_this_sec >= cfg->pps_limit) {
          usleep(100);
          continue;
        }
      }

      if (xsk_ring_prod__reserve(&xsk_info.tx, BATCH_SIZE, &idx_p) ==
          BATCH_SIZE) {
        int packets_to_send = 0;
        for (int i = 0; i < BATCH_SIZE; i++) {
          if (current_ip_int >= end_ip_int)
            break;

          uint64_t addr = (outstanding % NUM_FRAMES) * FRAME_SIZE;
          outstanding++;

          char *pkt = (char *)cfg->umem->buffer + addr;
          struct xdp_desc *desc =
              xsk_ring_prod__tx_desc(&xsk_info.tx, idx_p + i);

          struct ethhdr *eth = (struct ethhdr *)pkt;
          memcpy(eth->h_dest, cfg->dest_mac, 6);
          memcpy(eth->h_source, cfg->src_mac, 6);
          eth->h_proto = htons(ETH_P_IP);

          struct iphdr *iph = (struct iphdr *)(eth + 1);
          iph->ihl = 5;
          iph->version = 4;
          iph->tos = 0;
          iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
          iph->id = htons(12345);
          iph->frag_off = 0;
          iph->ttl = 64;
          iph->protocol = IPPROTO_TCP;
          struct in_addr saddr;
          inet_aton(cfg->source_ip_str, &saddr);
          iph->saddr = saddr.s_addr;
          iph->daddr = htonl(current_ip_int);
          iph->check = 0;
          iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

          struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
          tcph->source = htons(TARGET_PORT);
          tcph->dest = htons(current_port);
          tcph->seq = htonl(0);
          tcph->ack_seq = 0;
          tcph->doff = 5;
          tcph->syn = 1;
          tcph->window = htons(5840);
          tcph->check = 0;
          tcph->check = tcp_checksum(iph, tcph);

          desc->addr = addr;
          desc->len = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                      sizeof(struct tcphdr);

          current_port++;
          if (current_port > cfg->end_port) {
            current_port = cfg->start_port;
            current_ip_int++;
          }

          scanned_count++;
          sent_this_sec++;
          packets_to_send++;
        }
        xsk_ring_prod__submit(&xsk_info.tx, packets_to_send);
        if (packets_to_send > 0) {
          if (sendto(xsk_socket__fd(xsk_info.xsk), NULL, 0, MSG_DONTWAIT, NULL,
                     0) < 0) {
          }
        }
      } else {
        sendto(xsk_socket__fd(xsk_info.xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
      }
    }
  }

  usleep(100000);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 7) {
    printf("Usage: sudo %s <interface> <target_file> <unused> <gateway_mac> "
           "<output_file> <pps> [-p start-end] [source_ip]\n",
           argv[0]);
    printf("Example: sudo %s ens160 cidrip-list.txt 0 ff:ff:ff:ff:ff:ff "
           "th.txt 5000000 -p 25565-65580 192.168.1.1\n",
           argv[0]);
    return 1;
  }

  const char *ifname = argv[1];
  const char *input_target = argv[2];

  load_targets(input_target);

  const char *mac_str = argv[4];
  output_file = strdup(argv[5]);
  long pps_limit = atol(argv[6]);

  unsigned char dest_mac[6];
  if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest_mac[0],
             &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4],
             &dest_mac[5]) != 6) {
    fprintf(stderr, "Invalid MAC address format\n");
    return 1;
  }

  results.capacity = 10000;
  results.ips = malloc(sizeof(char *) * results.capacity);
  results.head = 0;
  results.tail = 0;
  results.count = 0;
  results.finished = false;
  pthread_mutex_init(&results.lock, NULL);
  pthread_cond_init(&results.not_empty, NULL);

  pthread_t meta_threads[MAX_METADATA_THREADS];
  for (int i = 0; i < MAX_METADATA_THREADS; i++) {
    pthread_create(&meta_threads[i], NULL, metadata_worker_func, NULL);
  }

  unsigned char src_mac[6];
  get_mac_address(ifname, src_mac);
  char src_ip[INET_ADDRSTRLEN];
  get_ip_address(ifname, src_ip);

  int start_port = 25565;
  int end_port = 25565;

  if (argc > 7) {
    for (int i = 7; i < argc; i++) {
      if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
        char *p = argv[i + 1];
        char *dash = strchr(p, '-');
        if (dash) {
          *dash = '\0';
          start_port = atoi(p);
          end_port = atoi(dash + 1);
        } else {
          start_port = atoi(p);
          end_port = start_port;
        }
        printf("Port Range: %d-%d\n", start_port, end_port);
        i++;
      } else {
        if (inet_pton(AF_INET, argv[i], &(struct in_addr){0}) == 1) {
          strncpy(src_ip, argv[i], INET_ADDRSTRLEN);
          printf("Overriding Source IP: %s\n", src_ip);
        }
      }
    }
  }

  printf("\n--- Configuration ---\n");
  printf("Interface: %s\n", ifname);
  printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1],
         src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
  printf("Dest MAC (Gateway): %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac[0],
         dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
  printf("Source IP: %s\n", src_ip);
  if (strncmp(src_ip, "192.168", 7) == 0 || strncmp(src_ip, "10.", 3) == 0 ||
      strncmp(src_ip, "172.", 4) == 0) {
    printf("\n[WARNING] You are using a Private IP (%s)!\n", src_ip);
    printf("If scanning the Internet, you MUST use your Public IP.\n");
    printf("Pass your public IP as the last argument.\n\n");
  }
  printf("Target File: %s\n", input_target);
  printf("PPS Limit: %ld\n", pps_limit);
  printf("---------------------\n\n");

  struct bpf_object *obj = bpf_object__open("scan_kern.o");
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "ERROR: Failed to open scan_kern.o\n");
    return 1;
  }
  if (bpf_object__load(obj)) {
    fprintf(stderr, "ERROR: Failed to load scan_kern.o\n");
    return 1;
  }
  global_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
  if (global_map_fd < 0) {
    fprintf(stderr, "ERROR: Failed to find xsks_map\n");
    return 1;
  }

  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "xdp_sock_prog");
  int prog_fd = bpf_program__fd(prog);
  int ifindex = if_nametoindex(ifname);
  printf("Debug: ifname='%s' -> ifindex=%d, prog_fd=%d\n", ifname, ifindex,
         prog_fd);

  if (ifindex == 0) {
    fprintf(stderr, "ERROR: Invalid interface name '%s'\n", ifname);
    return 1;
  }

  int flags = XDP_FLAGS_DRV_MODE;
  if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL) < 0) {
    fprintf(stderr,
            "Native (Driver) mode failed, trying SKB (Generic) mode...\n");
    flags = XDP_FLAGS_SKB_MODE;
    if (bpf_xdp_attach(ifindex, prog_fd, flags, NULL) < 0) {
      perror("ERROR: Failed to attach XDP program");
      return 1;
    }
  }

  int size = NUM_FRAMES * FRAME_SIZE;
  void *bufs;
  posix_memalign(&bufs, getpagesize(), size);
  struct xsk_umem_info *umem = configure_umem(bufs, size);

  struct xdp_worker_config cfg = {.queue_id = 0,
                                  .ifname = ifname,
                                  .start_ip_str = "0.0.0.0",
                                  .num_ips = 0,
                                  .start_port = start_port,
                                  .end_port = end_port,
                                  .pps_limit = pps_limit,
                                  .umem = umem,
                                  .shared_umem = 0};
  memcpy(cfg.src_mac, src_mac, 6);
  memcpy(cfg.dest_mac, dest_mac, 6);
  strncpy(cfg.source_ip_str, src_ip, INET_ADDRSTRLEN);

  struct sniffer_config *sniff_cfg = malloc(sizeof(struct sniffer_config));
  strncpy(sniff_cfg->ifname, ifname, IFNAMSIZ - 1);
  sniff_cfg->start_port = start_port;
  sniff_cfg->end_port = end_port;

  pthread_t sniffer_thread;
  pthread_create(&sniffer_thread, NULL, raw_socket_sniffer, (void *)sniff_cfg);

  pthread_t xdp_thread;
  pthread_create(&xdp_thread, NULL, xdp_worker_func, &cfg);

  while (1) {
    printf("\rScanned: %lu | Found: %lu | Queue: %d", scanned_count,
           found_count, results.count);
    fflush(stdout);
    sleep(1);
  }

  return 0;
}
