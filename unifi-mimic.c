#include <libnet.h>
#include <ifaddrs.h>

#define MCAST_PORT 10001
#define MCAST_ADDR "233.89.188.1"

static int run = 0, discover = 0, sd = -1;
static char *ipaddr = NULL;
static uint8_t *pkt_buf;
static long pkt_s;

static void load_packet()
{
  FILE *fp;

  fp = fopen(ipaddr, "r");
  if (fp == NULL) {
    fprintf(stderr, "Unable to open: %s\n", strerror(errno));
    exit(1);
  }

  fseek(fp, 0, SEEK_END);
  pkt_s = ftell(fp) / 2;
  rewind(fp);

  pkt_buf = (uint8_t *)malloc(pkt_s);
  memset(pkt_buf, 0, pkt_s);

  int i = 0;
  while (i < pkt_s && fscanf(fp, "%2hhx", &pkt_buf[i++]) == 1);

  fclose(fp);
}

static void send_packet(const uint16_t dport, char *dst)
{
  char errbuf[LIBNET_ERRBUF_SIZE];
  uint32_t src_ip, dst_ip;
  libnet_t *ln;
  libnet_ptag_t udp = 0, ip = 0;

  if ((ln = libnet_init(LIBNET_RAW4, NULL, errbuf)) == NULL) {
    fprintf(stderr, "Failed to create libnet context: %s\n", errbuf);
    exit(1);
  }

  src_ip = libnet_name2addr4(ln, ipaddr, LIBNET_DONT_RESOLVE);
  dst_ip = libnet_name2addr4(ln, dst, LIBNET_DONT_RESOLVE);

  if (libnet_build_udp(
    MCAST_PORT,
    dport,
    LIBNET_UDP_H + pkt_s,
    0,
    pkt_buf,
    pkt_s,
    ln,
    udp) == -1) {

    fprintf(stderr, "Failed to build UDP header: %s\n", libnet_geterror(ln));
    libnet_destroy(ln);
    exit(1);
  }

  if (libnet_build_ipv4(
    LIBNET_IPV4_H + LIBNET_UDP_H + pkt_s,
    0,
    12345,
    0,
    255,
    IPPROTO_UDP,
    0,
    src_ip,
    dst_ip,
    NULL,
    0,
    ln,
    ip) == -1) {

    fprintf(stderr, "Failed to build IP header: %s\n", libnet_geterror(ln));
    libnet_destroy(ln);
    exit(1);
  }
      
  libnet_write(ln);
  libnet_destroy(ln); 
}

static int iface_get_addr(const char *iface, struct in_addr *addr)
{
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    fprintf(stderr, "Error getting interface address: %s\n", strerror(errno));
    return -1;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;
    if (ifa->ifa_addr->sa_family != AF_INET) continue;
    if (strcmp(ifa->ifa_name, iface)) continue;
    memcpy(addr, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, sizeof(struct in_addr));
    break;
  }

  freeifaddrs(ifaddr);
  return 0;
}

static void unifi_discover(const char *iface)
{
  int rc;
  char buf[1024] = {1, 0, 0, 0};
  struct sockaddr_in sa_mcast, sa_remote;
  struct in_addr if_addr;
  FILE *fp;

  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
    exit(1);
  }

  rc = iface_get_addr(iface, &if_addr);
  if (rc < 0) {
    fprintf(stderr, "Unable to get IP from %s\n", iface);
    exit(rc);
  }

  rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&if_addr, sizeof(if_addr));
  if (rc < 0) {
    fprintf(stderr, "Error multicast interface: %s\n", strerror(errno));
    exit(rc);
  }

  memset(&sa_mcast, 0, sizeof(sa_mcast));
  sa_mcast.sin_family = AF_INET;
  sa_mcast.sin_addr.s_addr = inet_addr(MCAST_ADDR);
  sa_mcast.sin_port = htons(MCAST_PORT);

  rc = sendto(sd, buf, 4, 0, (struct sockaddr *)&sa_mcast, sizeof(sa_mcast));
  if (rc < 0) {
    fprintf(stderr, "Error sending discovery packet: %s\n", strerror(errno));
    exit(rc);
  }

  printf("Packet sent to %s:%d\n",
    inet_ntoa(sa_mcast.sin_addr), ntohs(sa_mcast.sin_port));

  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;

  rc = setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
  if (rc < 0) {
    fprintf(stderr, "Error setting timeout: %s\n", strerror(errno));
    exit(rc);
  }

  int c = 10; // TODO: accept as argument?
  ssize_t bytes;
  socklen_t slen = sizeof(struct sockaddr_in);

  while (c-- > 0) {
    memset(buf, 0, sizeof(buf));
    bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&sa_remote, &slen);

    if (bytes < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "Error reading packet: %s\n", strerror(errno));
        continue;
      }
    }

    if (bytes > 0) {
      printf("Packet from %s\n", inet_ntoa(sa_remote.sin_addr));

      fp = fopen(inet_ntoa(sa_remote.sin_addr), "w");
      if (fp == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", strerror(errno));
        continue;
      }

      for (int i = 0; i < bytes; i++) fprintf(fp, "%02x", buf[i]);
      fclose(fp);
    }
  }
}

void unifi_listen(const char *iface)
{
  struct sockaddr_in sa_mcast, sa_remote, sa_dst;
  struct ip_mreq mreq;
  char buf[1024];

  memset(&sa_mcast, 0, sizeof(sa_mcast));
  memset(&sa_dst, 0, sizeof(sa_dst));
  memset(buf, 0, sizeof(buf));

  sa_mcast.sin_family = AF_INET;
  sa_mcast.sin_port = htons(MCAST_PORT);
  sa_mcast.sin_addr.s_addr = inet_addr(MCAST_ADDR);

  sa_dst.sin_family = AF_INET;
  sa_dst.sin_port = htons(MCAST_PORT);
  sa_dst.sin_addr.s_addr = inet_addr(ipaddr);

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
    exit(1);
  }

  int reuse = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
    fprintf(stderr, "Failed to set socket options: %s\n", strerror(errno));
    exit(1);
  }

  if (bind(sd, (struct sockaddr *)&sa_mcast, sizeof(sa_mcast)) == -1) {
    fprintf(stderr, "Failed to bind: %s\n", strerror(errno));
    exit(1);
  }

  printf("Listening on %s:%d\n",
    inet_ntoa(sa_mcast.sin_addr), ntohs(sa_mcast.sin_port));

  mreq.imr_multiaddr = sa_mcast.sin_addr;
  iface_get_addr(iface, &mreq.imr_interface);
  if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == -1) {
    fprintf(stderr, "Failed to join multicast group: %s\n", strerror(errno));
    exit(1);
  }

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 10;

  if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    fprintf(stderr, "Failed to set timeout: %s\n", strerror(errno));
    exit(1);
  }

  socklen_t slen = sizeof(struct sockaddr_in);

  while (run) {
    if (recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&sa_remote, &slen) > 0) {
      send_packet(ntohs(sa_remote.sin_port), inet_ntoa(sa_remote.sin_addr));
    }
  }
}

static void print_usage()
{
  fprintf(stderr, "unifi-mimic help\n\n");
  fprintf(stderr, " Discover:\n");
  fprintf(stderr, "  -D    Discover UniFi devices\n");
  fprintf(stderr, "        Requires -i\n\n");
  fprintf(stderr, " Listen:\n");
  fprintf(stderr, "  -L    Listen and respond to UniFi Protect app requests\n");
  fprintf(stderr, "        Requires -i and -p\n\n");
  fprintf(stderr, " Options:\n");
  fprintf(stderr, "  -i <interface>\n     Specify interface\n\n");
  fprintf(stderr, "  -p <packet file>\n     Load packet file\n\n");
  fprintf(stderr, "  -f Run in background.\n\n");
  fprintf(stderr, "  -h Display this.\n\n");
  exit(0);
}

void onexit()
{
  printf("Exiting...\n");
  if (pkt_buf != NULL) free(pkt_buf);
  if (sd > -1) close(sd);
  run = 0;
}

int main(int argc, char **argv)
{
  int opt;
  char *iface = NULL;
  struct sigaction sa;
  pid_t pid;

  for (optind = 1;;) {
    if ((opt = getopt(argc, argv, "DLp:fi:h")) == -1) break;

    switch (opt) {
    case 'D':
      discover = 1;
      break;

    case 'L':
      run = 1;
      break;

    case 'p':
      ipaddr = strdup(optarg);
      break;

    case 'f':
      pid = fork();

      if (pid < 0) {
        fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
        exit(0);
      }

      if (pid > 0) exit(0);
      break;

    case 'i':
      iface = strdup(optarg);
      break;

    case 'h':
      print_usage();
      break;
    }
  }

  sa.sa_handler = onexit;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  if (discover && run) {
    fprintf(stderr, "Cannot discover and listen.\n");
    return -1;
  }

  if (!discover && !run) {
    print_usage();
  }

  if (discover && !iface) {
    fprintf(stderr, "Interface is required. Use -i <interface>\n");
    return -1;
  }

  if (discover && iface != NULL) {
    unifi_discover(iface);
  }

  if (run && !ipaddr) {
    fprintf(stderr, "Packet file is required. Use -p <packet file>\n");
    return -1;
  }

  if (run && !iface) {
    fprintf(stderr, "Interface is required. Use -i <interface>\n");
    return -1;
  }

  if (run && ipaddr != NULL && iface != NULL) {
    load_packet();
    unifi_listen(iface);
  }

  return 0;
}

