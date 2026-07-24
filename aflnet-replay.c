#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf,
                                         unsigned int buf_size,
                                         unsigned int* state_count_ref) = NULL;

typedef enum {
  REPLAY_FIX_NONE = 0,
  REPLAY_FIX_MODBUS,
  REPLAY_FIX_BACNET,
  REPLAY_FIX_IEC61850,
  REPLAY_FIX_IEC104
} replay_fix_mode_t;

char *get_test_case(char* packet_file, int *fsize)
{
  s32 fd = open(packet_file, O_RDONLY);

  if (fd < 0) {
    fprintf(stderr, "[AFLNet-replay] Error opening file %s\n", packet_file);
    exit(1);
  }

  *fsize = lseek(fd, 0, SEEK_END);

  if (*fsize < 0) {
    fprintf(stderr, "[AFLNet-replay] Error getting file size %s\n", packet_file);
    close(fd);
    exit(1);
  }

  lseek(fd, 0, SEEK_SET);

  char *buf = ck_alloc(*fsize ? *fsize : 1);

  if (*fsize > 0) {
    ck_read(fd, buf, *fsize, "packet file");
  }

  close(fd);

  return buf;
}

static int is_udp_protocol(const char *protocol)
{
  if (!strcmp(protocol, "DTLS12")) return 1;
  if (!strcmp(protocol, "DNS"))    return 1;
  if (!strcmp(protocol, "SIP"))    return 1;
  if (!strcmp(protocol, "BACNET")) return 1;

  return 0;
}

static int is_iec104_protocol(const char *protocol)
{
  if (!strcmp(protocol, "IEC104"))        return 1;
  if (!strcmp(protocol, "CS104"))         return 1;
  if (!strcmp(protocol, "IEC60870"))      return 1;
  if (!strcmp(protocol, "IEC60870-5-104")) return 1;

  return 0;
}

static region_t *extract_regions_by_mode(replay_fix_mode_t mode,
                                          unsigned char *buf,
                                          unsigned int buf_size,
                                          unsigned int *region_count)
{
  *region_count = 0;

  if (mode == REPLAY_FIX_MODBUS) {
    return extract_requests_modbus(buf, buf_size, region_count);
  }

  if (mode == REPLAY_FIX_BACNET) {
    return extract_requests_bacnet(buf, buf_size, region_count);
  }

  if (mode == REPLAY_FIX_IEC61850) {
    return extract_requests_iec61850(buf, buf_size, region_count);
  }

  if (mode == REPLAY_FIX_IEC104) {
    return extract_requests_iec104(buf, buf_size, region_count);
  }

  return NULL;
}

static unsigned int fix_message_by_mode(replay_fix_mode_t mode,
                                        unsigned char *buf,
                                        unsigned int buf_size)
{
  if (mode == REPLAY_FIX_MODBUS) {
    return modbus_fix_request_message(buf, buf_size);
  }

  if (mode == REPLAY_FIX_BACNET) {
    return bacnet_fix_request_message(buf, buf_size);
  }

  if (mode == REPLAY_FIX_IEC61850) {
    return iec61850_fix_request_message(buf, buf_size);
  }

  if (mode == REPLAY_FIX_IEC104) {
    return iec104_fix_request_message(buf, buf_size);
  }

  return buf_size;
}

static void free_regions(region_t *regions, unsigned int region_count)
{
  unsigned int i;

  if (regions == NULL) {
    return;
  }

  for (i = 0; i < region_count; i++) {
    if (regions[i].state_sequence != NULL) {
      ck_free(regions[i].state_sequence);
    }
  }

  ck_free(regions);
}

static void print_response_details(replay_fix_mode_t mode,
                                   char *response_buf,
                                   int response_buf_size)
{
  unsigned int i;

  if (response_buf == NULL || response_buf_size <= 0) {
    fprintf(stderr, "<empty response>");
    return;
  }

  /*
   * IEC104/CS104 is binary. Hex output is more useful for replay analysis.
   * Keep the original printable-byte behavior for other protocols.
   */
  if (mode == REPLAY_FIX_IEC104) {
    for (i = 0; i < (unsigned int)response_buf_size; i++) {
      fprintf(stderr, "%02x", (unsigned char)response_buf[i]);

      if (i + 1 < (unsigned int)response_buf_size) {
        fprintf(stderr, " ");
      }
    }
  } else {
    for (i = 0; i < (unsigned int)response_buf_size; i++) {
      fprintf(stderr, "%c", response_buf[i]);
    }
  }
}

/*
 * Expected arguments:
 *
 *   1. Path to the test case, e.g. crash-triggering input
 *   2. Application protocol, e.g. RTSP, FTP, MODBUS, BACNET, IEC61850, IEC104
 *   3. Server's network port
 *
 * Optional:
 *
 *   4. First response poll timeout, default 1
 *   5. Follow-up socket timeout, default 1000
 *
 * Example for lib60870-C v2.3.6 examples/cs104_server/simple_server:
 *
 *   ./aflnet-replay testcase IEC104 2404
 *   ./aflnet-replay testcase CS104 2404
 *   ./aflnet-replay testcase IEC60870 2404
 */

int main(int argc, char* argv[])
{
  int portno, n;
  int sockfd;
  struct sockaddr_in serv_addr;

  char* buf = NULL;
  char* response_buf = NULL;

  int buf_size = 0;
  int response_buf_size = 0;

  unsigned int i;
  unsigned int state_count = 0;
  unsigned int *state_sequence = NULL;

  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;

  replay_fix_mode_t replay_fix_mode = REPLAY_FIX_NONE;

  if (argc < 4) {
    PFATAL("Usage: ./aflnet-replay packet_file protocol port [first_resp_timeout [follow-up_resp_timeout]]");
  }

  if (!strcmp(argv[2], "RTSP")) {
    extract_response_codes = &extract_response_codes_rtsp;
  } else if (!strcmp(argv[2], "FTP")) {
    extract_response_codes = &extract_response_codes_ftp;
  } else if (!strcmp(argv[2], "DNS")) {
    extract_response_codes = &extract_response_codes_dns;
  } else if (!strcmp(argv[2], "DTLS12")) {
    extract_response_codes = &extract_response_codes_dtls12;
  } else if (!strcmp(argv[2], "DICOM")) {
    extract_response_codes = &extract_response_codes_dicom;
  } else if (!strcmp(argv[2], "SMTP")) {
    extract_response_codes = &extract_response_codes_smtp;
  } else if (!strcmp(argv[2], "SSH")) {
    extract_response_codes = &extract_response_codes_ssh;
  } else if (!strcmp(argv[2], "TLS")) {
    extract_response_codes = &extract_response_codes_tls;
  } else if (!strcmp(argv[2], "SIP")) {
    extract_response_codes = &extract_response_codes_sip;
  } else if (!strcmp(argv[2], "HTTP")) {
    extract_response_codes = &extract_response_codes_http;
  } else if (!strcmp(argv[2], "IPP")) {
    extract_response_codes = &extract_response_codes_ipp;
  } else if (!strcmp(argv[2], "MODBUS")) {
    extract_response_codes = &extract_response_codes_modbus;
    replay_fix_mode = REPLAY_FIX_MODBUS;
  } else if (!strcmp(argv[2], "BACNET")) {
    extract_response_codes = &extract_response_codes_bacnet;
    replay_fix_mode = REPLAY_FIX_BACNET;
  } else if (!strcmp(argv[2], "IEC61850") || !strcmp(argv[2], "MMS")) {
    /*
     * libiec61850 MMS over ISO-on-TCP:
     *   TCP -> TPKT -> COTP -> Session/Presentation/ACSE -> MMS
     *
     * Replay must be consistent with fuzzing-time send repair:
     *   - split testcase by TPKT regions;
     *   - repair only TPKT version/reserved/length before sending;
     *   - send every TPKT frame over the same TCP connection.
     */
    extract_response_codes = &extract_response_codes_iec61850;
    replay_fix_mode = REPLAY_FIX_IEC61850;
  } else if (is_iec104_protocol(argv[2])) {
    /*
     * lib60870-C examples/cs104_server/simple_server:
     *
     *   IEC 60870-5-104 / CS104 over TCP.
     *   APDU format:
     *     0x68 | length | control[4] | optional ASDU
     *
     * Replay must be consistent with fuzzing-time send repair:
     *   - split testcase by CS104 APDU length;
     *   - repair only 0x68 start byte, APDU length and minimal APCI bits;
     *   - send every CS104 APDU over the same TCP connection.
     */
    extract_response_codes = &extract_response_codes_iec104;
    replay_fix_mode = REPLAY_FIX_IEC104;
  } else {
    fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]);
    exit(1);
  }

  portno = atoi(argv[3]);

  if (portno <= 0 || portno > 65535) {
    fprintf(stderr, "[AFLNet-replay] Invalid port: %s\n", argv[3]);
    exit(1);
  }

  if (argc > 4) {
    poll_timeout = atoi(argv[4]);

    if (argc > 5) {
      socket_timeout = atoi(argv[5]);
    }
  }

  usleep(server_wait_usecs);

  /*
   * Keep original transport behavior for existing protocols.
   *
   * BACNET is BACnet/IP over UDP.
   * IEC61850/MMS is TCP.
   * IEC104/CS104/lib60870 is TCP and must not be added to this UDP list.
   */
  if (is_udp_protocol(argv[2])) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  /*
   * Set timeout for socket sending.
   * net_recv also receives the timeout value explicitly.
   */
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, 0, sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    /*
     * If connection fails, retry briefly. Server startup time may vary.
     *
     * For UDP, connect() only records peer address and usually succeeds even
     * when the remote server is not fully initialized.
     */
    for (n = 0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
        break;
      }

      usleep(1000);
    }

    if (n == 1000) {
      close(sockfd);
      return 1;
    }
  }

  buf = get_test_case(argv[1], &buf_size);

  /*
   * Protocol-aware replay path.
   *
   * MODBUS:
   *   - split by Modbus TCP ADU regions;
   *   - repair MBAP fields before sending;
   *   - send each ADU over TCP.
   *
   * BACNET:
   *   - split by BACnet/IP BVLC Length;
   *   - repair BVLC Type/Length/NPDU version;
   *   - send each BVLL packet as one UDP datagram.
   *
   * IEC61850:
   *   - split by TPKT length;
   *   - repair only TPKT version/reserved/length;
   *   - send each TPKT frame over the same TCP connection.
   *
   * IEC104/CS104/lib60870:
   *   - split by CS104 APDU length;
   *   - repair only start byte, APDU length and minimal APCI type bits;
   *   - send each APDU over the same TCP connection.
   *
   * All other protocols keep AFLNet replay's original whole-testcase send path.
   */
  if (replay_fix_mode != REPLAY_FIX_NONE) {
    unsigned int region_count = 0;
    region_t *regions = NULL;

    regions = extract_regions_by_mode(replay_fix_mode,
                                      (unsigned char *)buf,
                                      buf_size,
                                      &region_count);

    if (regions == NULL || region_count == 0) {
      /*
       * Fallback:
       * If the request extractor cannot split regions, repair and send the
       * whole testcase once.
       */
      unsigned char *fixed_buf = NULL;
      unsigned int send_size = buf_size;

      if (send_size > 0) {
        fixed_buf = (unsigned char *)ck_alloc(send_size);
        memcpy(fixed_buf, buf, send_size);

        send_size = fix_message_by_mode(replay_fix_mode, fixed_buf, send_size);

        if (send_size > 0) {
          n = net_send(sockfd, timeout, (char *)fixed_buf, send_size);
          (void)n;
        }

        ck_free(fixed_buf);
      }
    } else {
      /*
       * Normal protocol-aware path:
       * Send every extracted protocol region separately.
       */
      for (i = 0; i < region_count; i++) {
        unsigned int start = regions[i].start_byte;
        unsigned int end = regions[i].end_byte;
        unsigned int msg_size;
        unsigned int send_size;
        unsigned char *msg_buf = NULL;

        if (start >= (unsigned int)buf_size) {
          continue;
        }

        if (end >= (unsigned int)buf_size) {
          end = buf_size - 1;
        }

        if (end < start) {
          continue;
        }

        msg_size = end - start + 1;

        if (msg_size == 0) {
          continue;
        }

        msg_buf = (unsigned char *)ck_alloc(msg_size);
        memcpy(msg_buf, buf + start, msg_size);

        send_size = fix_message_by_mode(replay_fix_mode, msg_buf, msg_size);

        if (send_size > 0) {
          n = net_send(sockfd, timeout, (char *)msg_buf, send_size);

          if (n != (int)send_size) {
            ck_free(msg_buf);
            break;
          }
        }

        ck_free(msg_buf);
      }
    }

    free_regions(regions, region_count);
  } else {
    /*
     * Original AFLNet replay behavior for all non-special-cased protocols.
     */
    n = net_send(sockfd, timeout, buf, buf_size);
    (void)n;
  }

  net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size);

  close(sockfd);

  state_sequence = (*extract_response_codes)((unsigned char *)response_buf,
                                             response_buf_size,
                                             &state_count);

  fprintf(stderr, "\n--------------------------------");
  fprintf(stderr, "\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr, "%d-", state_sequence[i]);
  }

  fprintf(stderr, "\n++++++++++++++++++++++++++++++++\nResponses in details:\n");

  print_response_details(replay_fix_mode, response_buf, response_buf_size);

  fprintf(stderr, "\n--------------------------------\n");

  if (state_sequence) ck_free(state_sequence);
  if (buf) ck_free(buf);
  if (response_buf) ck_free(response_buf);

  return 0;
}