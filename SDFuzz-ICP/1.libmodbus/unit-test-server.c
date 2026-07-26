/*
 * Copyright © Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * SDFuzz/stdin harness adaptation:
 * - Keeps the original libmodbus unit-test server initialization, mapping setup,
 *   special server-side test behavior, modbus_receive(), and modbus_reply() path.
 * - Replaces external TCP/TCP_PI/RTU listen/connect with a local socketpair.
 * - Reads one fuzzing testcase stream from stdin and feeds it to the libmodbus
 *   context as if it had been received from a connected peer.
 *
 * Intended usage:
 *   ./unit-test-server-sdfuzz [tcp|tcppi|rtu] < testcase.bin
 *
 * For AFL/SDFuzz-style @@ input, wrap it as:
 *   sh -c './unit-test-server-sdfuzz tcp < "$1"' sh @@
 */

#include <errno.h>
#include <modbus.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// clang-format off
#ifdef _WIN32
# include <winsock2.h>
#else
# include <sys/socket.h>
#endif

/* For MinGW */
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
// clang-format on

#include "unit-test.h"

enum {
    TCP,
    TCP_PI,
    RTU
};

#ifndef FUZZ_INPUT_MAX
#define FUZZ_INPUT_MAX 4096
#endif

static int read_stdin_all(uint8_t *buf, int max_len)
{
    int total = 0;

    while (total < max_len) {
        ssize_t n = read(STDIN_FILENO, buf + total, (size_t) (max_len - total));
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total += (int) n;
    }

    return total;
}

static int write_all(int fd, const uint8_t *buf, int len)
{
    int total = 0;

    while (total < len) {
        ssize_t n = write(fd, buf + total, (size_t) (len - total));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        total += (int) n;
    }

    return total;
}

#ifndef _WIN32
static int setup_fuzz_socketpair(modbus_t *ctx, const uint8_t *input, int input_len, int *peer_fd)
{
    int sp[2] = {-1, -1};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1) {
        return -1;
    }

    if (input_len > 0 && write_all(sp[1], input, input_len) == -1) {
        close(sp[0]);
        close(sp[1]);
        return -1;
    }

    /* No more request bytes will be sent by the fuzzing peer.  Keep the peer
       descriptor open so replies emitted by modbus_reply() have a valid sink. */
    shutdown(sp[1], SHUT_WR);

    modbus_set_socket(ctx, sp[0]);
    *peer_fd = sp[1];
    return sp[0];
}
#endif

int main(int argc, char *argv[])
{
    int s = -1;
    int peer_fd = -1;
    modbus_t *ctx = NULL;
    modbus_mapping_t *mb_mapping = NULL;
    int rc;
    int i;
    int use_backend;
    uint8_t *query = NULL;
    uint8_t *fuzz_input = NULL;
    int fuzz_input_len;
    int header_length;
    char *ip_or_device = NULL;
    const char *debug_env;

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#else
    fprintf(stderr, "This stdin/socketpair fuzz harness is intended for POSIX systems.\n");
    return -1;
#endif

    if (argc > 1) {
        if (strcmp(argv[1], "tcp") == 0) {
            use_backend = TCP;
        } else if (strcmp(argv[1], "tcppi") == 0) {
            use_backend = TCP_PI;
        } else if (strcmp(argv[1], "rtu") == 0) {
            use_backend = RTU;
        } else {
            printf("Modbus server stdin harness for unit testing and fuzzing.\n");
            printf("Usage:\n  %s [tcp|tcppi|rtu] < testcase.bin\n", argv[0]);
            printf("Eg. %s tcp < seeds/fc03.bin\n\n", argv[0]);
            return -1;
        }
    } else {
        /* By default */
        use_backend = TCP;
    }

    if (argc > 2) {
        ip_or_device = argv[2];
    } else {
        switch (use_backend) {
        case TCP:
            ip_or_device = "127.0.0.1";
            break;
        case TCP_PI:
            ip_or_device = "::1";
            break;
        case RTU:
            ip_or_device = "/dev/ttyUSB0";
            break;
        default:
            break;
        }
    }

    if (use_backend == TCP) {
        ctx = modbus_new_tcp(ip_or_device, 1502);
        query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
    } else if (use_backend == TCP_PI) {
        ctx = modbus_new_tcp_pi(ip_or_device, "1502");
        query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
    } else {
        ctx = modbus_new_rtu(ip_or_device, 115200, 'N', 8, 1);
        if (ctx != NULL) {
            modbus_set_slave(ctx, SERVER_ID);
        }
        query = malloc(MODBUS_RTU_MAX_ADU_LENGTH);
    }

    if (ctx == NULL || query == NULL) {
        fprintf(stderr, "Failed to allocate libmodbus context or query buffer\n");
        free(query);
        if (ctx != NULL) {
            modbus_free(ctx);
        }
        return -1;
    }

    fuzz_input = malloc(FUZZ_INPUT_MAX);
    if (fuzz_input == NULL) {
        fprintf(stderr, "Failed to allocate fuzz input buffer\n");
        free(query);
        modbus_free(ctx);
        return -1;
    }

    fuzz_input_len = read_stdin_all(fuzz_input, FUZZ_INPUT_MAX);
    if (fuzz_input_len <= 0) {
        free(fuzz_input);
        free(query);
        modbus_free(ctx);
        return 0;
    }

#ifndef _WIN32
    s = setup_fuzz_socketpair(ctx, fuzz_input, fuzz_input_len, &peer_fd);
    if (s == -1) {
        fprintf(stderr, "Failed to create or feed local fuzz socketpair: %s\n", strerror(errno));
        free(fuzz_input);
        free(query);
        modbus_free(ctx);
        return -1;
    }
#endif

    header_length = modbus_get_header_length(ctx);

    debug_env = getenv("LIBMODBUS_FUZZ_DEBUG");
    modbus_set_debug(ctx, (debug_env != NULL && strcmp(debug_env, "0") != 0) ? TRUE : FALSE);

    /* Keep receive operations bounded under truncated or length-inconsistent inputs. */
    modbus_set_response_timeout(ctx, 0, 10000);
    modbus_set_byte_timeout(ctx, 0, 10000);

    mb_mapping = modbus_mapping_new_start_address(UT_BITS_ADDRESS,
                                                  UT_BITS_NB,
                                                  UT_INPUT_BITS_ADDRESS,
                                                  UT_INPUT_BITS_NB,
                                                  UT_REGISTERS_ADDRESS,
                                                  UT_REGISTERS_NB_MAX,
                                                  UT_INPUT_REGISTERS_ADDRESS,
                                                  UT_INPUT_REGISTERS_NB);
    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n", modbus_strerror(errno));
        free(fuzz_input);
        free(query);
        modbus_close(ctx);
        modbus_free(ctx);
        if (peer_fd != -1) {
            close(peer_fd);
        }
        return -1;
    }

    /* Examples from PI_MODBUS_300.pdf.
       Only the read-only input values are assigned. */

    /* Initialize input values that's can be only done server side. */
    modbus_set_bits_from_bytes(
        mb_mapping->tab_input_bits, 0, UT_INPUT_BITS_NB, UT_INPUT_BITS_TAB);

    /* Initialize values of INPUT REGISTERS */
    for (i = 0; i < UT_INPUT_REGISTERS_NB; i++) {
        mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
    }

    for (;;) {
        do {
            rc = modbus_receive(ctx, query);
            /* Filtered queries return 0 */
        } while (rc == 0);

        /* The connection is not closed on errors which require no reply such as
           bad CRC in RTU. */
        if (rc == -1) {
            if (errno == EMBBADCRC) {
                /* Wait for the next request, the query is unusable */
                continue;
            }
            /* Quit */
            break;
        }

        uint8_t function = query[header_length];
        uint16_t address = 0;

        /* Only read address when the request carries one (some function
           codes like FC 0x07/0x11 have no address in the PDU). */
        if (rc >= header_length + 3)
            address = MODBUS_GET_INT16_FROM_INT8(query, header_length + 1);

        /** Special server behavior to test client **/
        if (function == MODBUS_FC_READ_HOLDING_REGISTERS) {
            if (rc >= header_length + 5 &&
                MODBUS_GET_INT16_FROM_INT8(query, header_length + 3) ==
                    UT_REGISTERS_NB_SPECIAL) {
                printf("Set an incorrect number of values\n");
                MODBUS_SET_INT16_TO_INT8(
                    query, header_length + 3, UT_REGISTERS_NB_SPECIAL - 1);
            } else if (address == UT_REGISTERS_ADDRESS_SPECIAL) {
                printf("Reply to this special register address by an exception\n");
                modbus_reply_exception(ctx, query, MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY);
                continue;
            } else if (address == UT_REGISTERS_ADDRESS_INVALID_TID_OR_SLAVE) {
                const int RAW_REQ_LENGTH = 5;
                uint8_t raw_req[] = {(use_backend == RTU) ? INVALID_SERVER_ID : 0xFF,
                                     0x03,
                                     0x02,
                                     0x00,
                                     0x00};

                printf("Reply with an invalid TID or slave\n");
                modbus_send_raw_request(ctx, raw_req, RAW_REQ_LENGTH * sizeof(uint8_t));
                continue;
            } else if (address == UT_REGISTERS_ADDRESS_SLEEP_500_MS) {
                printf("Sleep 0.5 s before replying\n");
                usleep(500000);
            } else if (address == UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS) {
                /* Test low level only available in TCP mode */
                /* Catch the reply and send reply byte a byte */
                uint8_t req[] = "\x00\x1C\x00\x00\x00\x05\xFF\x03\x02\x00\x00";
                int req_length = 11;
                int w_s = modbus_get_socket(ctx);
                if (w_s == -1) {
                    fprintf(stderr, "Unable to get a valid socket in special test\n");
                    continue;
                }

                /* Copy TID */
                req[1] = query[1];
                for (i = 0; i < req_length; i++) {
                    printf("(%.2X)", req[i]);
                    usleep(5000);
                    rc = send(w_s, (const char *) (req + i), 1, MSG_NOSIGNAL);
                    if (rc == -1) {
                        break;
                    }
                }
                continue;
            }
        } else if (function == MODBUS_FC_WRITE_SINGLE_COIL) {
            if (address == UT_BITS_ADDRESS_INVALID_REQUEST_LENGTH) {
                // The valid length is lengths of header + checkum + FC + address + value
                // (max 12)
                rc = 34;
                printf(
                    "Special modbus_write_bit detected. Inject a wrong length value (%d) "
                    "in modbus_reply\n",
                    rc);
            }
        } else if (function == MODBUS_FC_WRITE_SINGLE_REGISTER) {
            if (address == UT_REGISTERS_ADDRESS_SPECIAL) {
                rc = 45;
                printf("Special modbus_write_register detected. Inject a wrong length "
                       "value (%d) in modbus_reply\n",
                       rc);
            }
        }

        rc = modbus_reply(ctx, query, rc, mb_mapping);
        if (rc == -1) {
            break;
        }
    }

    printf("Quit the loop: %s\n", modbus_strerror(errno));

    modbus_mapping_free(mb_mapping);
    free(fuzz_input);
    free(query);
    /* The fuzz harness uses modbus_set_socket(ctx, s), so modbus_close(ctx)
       closes the libmodbus side of the socketpair. */
    modbus_close(ctx);
    modbus_free(ctx);

    if (peer_fd != -1) {
        close(peer_fd);
    }

    return 0;
}
