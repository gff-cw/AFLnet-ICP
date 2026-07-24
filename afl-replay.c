#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

char *get_test_case(char* packet_file, int *fsize)
{
  /* open packet file */
  s32 fd = open(packet_file, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "[AFLNet-replay] Error opening file %s\n", packet_file);
    exit(1);
  }

  *fsize = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  /* allocate buffer to read the file */
  char *buf = ck_alloc(*fsize);
  ck_read(fd, buf, *fsize, "packet file");

  close(fd);

  return buf;
}

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout, default 1
5. Follow-up responses timeout, default 1000
*/

int main(int argc, char* argv[])
{
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int buf_size = 0;
  int response_buf_size = 0;
  unsigned int i, state_count;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;

  u8 modbus_mode = 0;
  u8 bacnet_mode = 0;

  if (argc < 4) {
    PFATAL("Usage: ./afl-replay packet_file protocol port [first_resp_timeout [follow-up_resp_timeout]]");
  }

  if (!strcmp(argv[2], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(argv[2], "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(argv[2], "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(argv[2], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(argv[2], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(argv[2], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(argv[2], "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(argv[2], "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(argv[2], "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(argv[2], "HTTP")) extract_response_codes = &extract_response_codes_http;
  else if (!strcmp(argv[2], "IPP")) extract_response_codes = &extract_response_codes_ipp;
  else if (!strcmp(argv[2], "MODBUS")) {
    extract_response_codes = &extract_response_codes_modbus;
    modbus_mode = 1;
  }
  else if (!strcmp(argv[2], "BACNET")) {
    extract_response_codes = &extract_response_codes_bacnet;
    bacnet_mode = 1;
  }
  else {
    fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]);
    exit(1);
  }

  portno = atoi(argv[3]);

  if (argc > 4) {
    poll_timeout = atoi(argv[4]);
    if (argc > 5) {
      socket_timeout = atoi(argv[5]);
    }
  }

  /* Wait for the server to initialize */
  usleep(server_wait_usecs);

  int sockfd;
  if ((!strcmp(argv[2], "DTLS12")) ||
      (!strcmp(argv[2], "DNS")) ||
      (!strcmp(argv[2], "SIP")) ||
      (!strcmp(argv[2], "BACNET"))) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  /*
   * Set timeout for socket data sending/receiving.
   * Otherwise replay may block for too long when the server stays alive.
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
     * If it cannot connect to the server under test, try again because the
     * server startup time may vary.
     *
     * For UDP, connect() only records the peer address and normally succeeds
     * even if the remote server has not fully initialized yet.
     */
    for (n = 0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }

    if (n == 1000) {
      close(sockfd);
      return 1;
    }
  }

  buf = get_test_case(argv[1], &buf_size);

  /*
   * MODBUS and BACNET need protocol-aware replay.
   *
   * MODBUS:
   *   split by Modbus TCP ADU regions, fix MBAP fields, send each ADU.
   *
   * BACNET:
   *   split by BACnet/IP BVLC Length, fix BVLC Type/Length/NPDU version,
   *   send each BVLL packet as one UDP datagram.
   */
  if (modbus_mode || bacnet_mode) {
    unsigned int region_count = 0;
    region_t *regions = NULL;

    if (modbus_mode) {
      regions = extract_requests_modbus((unsigned char *)buf,
                                        buf_size,
                                        &region_count);
    } else if (bacnet_mode) {
      regions = extract_requests_bacnet((unsigned char *)buf,
                                        buf_size,
                                        &region_count);
    }

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

        if (modbus_mode) {
          send_size = modbus_fix_request_message(fixed_buf, send_size);
        } else if (bacnet_mode) {
          send_size = bacnet_fix_request_message(fixed_buf, send_size);
        }

        if (send_size > 0) {
          n = net_send(sockfd, timeout, (char *)fixed_buf, send_size);
        }

        ck_free(fixed_buf);
      }
    } else {
      /*
       * Normal path:
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

        if (modbus_mode) {
          send_size = modbus_fix_request_message(msg_buf, msg_size);
        } else {
          send_size = bacnet_fix_request_message(msg_buf, msg_size);
        }

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

    if (regions != NULL) {
      for (i = 0; i < region_count; i++) {
        if (regions[i].state_sequence != NULL) {
          ck_free(regions[i].state_sequence);
        }
      }

      ck_free(regions);
    }
  } else {
    /*
     * Other protocols keep AFLNet replay's original behavior.
     */
    n = net_send(sockfd, timeout, buf, buf_size);
  }

  /* receive server responses */
  net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size);

  close(sockfd);

  /* Extract response codes */
  state_sequence = (*extract_response_codes)(response_buf,
                                             response_buf_size,
                                             &state_count);

  fprintf(stderr, "\n--------------------------------");
  fprintf(stderr, "\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr, "%d-", state_sequence[i]);
  }

  fprintf(stderr, "\n++++++++++++++++++++++++++++++++\nResponses in details:\n");

  for (i = 0; i < (unsigned int)response_buf_size; i++) {
    fprintf(stderr, "%c", response_buf[i]);
  }

  fprintf(stderr, "\n--------------------------------");

  /* Free memory */
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  if (response_buf) ck_free(response_buf);

  return 0;
}