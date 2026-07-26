/*
 *  server_example_basic_io_sdfuzz_stdin.c
 *
 *  SDFuzz/AFL-style stdin harness for libIEC61850 1.6.1
 *  based on examples/server_example_basic_io/server_example_basic_io.c
 *
 *  Usage examples:
 *      ./server_example_basic_io_sdfuzz_stdin < testcase.bin
 *      ./server_example_basic_io_sdfuzz_stdin 8102 < testcase.bin
 *
 *  This program intentionally does not require "@@". It reads one test case
 *  from stdin, starts the original IEC 61850 server locally, connects back to
 *  it through 127.0.0.1, sends the stdin bytes as the network byte stream, lets
 *  the real server path process the input briefly, and then exits.
 */

#include "iec61850_server.h"
#include "hal_thread.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "static_model.h"

#ifndef SDFUZZ_MAX_STDIN_SIZE
#define SDFUZZ_MAX_STDIN_SIZE (1024U * 1024U)
#endif

#ifndef SDFUZZ_CONNECT_RETRIES
#define SDFUZZ_CONNECT_RETRIES 100
#endif

#ifndef SDFUZZ_POST_SEND_SLEEP_MS
#define SDFUZZ_POST_SEND_SLEEP_MS 200
#endif

#ifndef SDFUZZ_PRE_SEND_TICKS
#define SDFUZZ_PRE_SEND_TICKS 2
#endif

#ifndef SDFUZZ_POST_SEND_TICKS
#define SDFUZZ_POST_SEND_TICKS 2
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int running = 0;
static IedServer iedServer = NULL;

void
sigint_handler(int signalId)
{
    (void) signalId;
    running = 0;
}

static ControlHandlerResult
controlHandlerForBinaryOutput(ControlAction action, void* parameter, MmsValue* value, bool test)
{
    (void) action;

    if (test)
        return CONTROL_RESULT_FAILED;

    if (MmsValue_getType(value) == MMS_BOOLEAN) {
        printf("received binary control command: ");

        if (MmsValue_getBoolean(value))
            printf("on\n");
        else
            printf("off\n");
    }
    else
        return CONTROL_RESULT_FAILED;

    uint64_t timeStamp = Hal_getTimeInMs();

    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO1) {
        IedServer_updateUTCTimeAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1_stVal, value);
    }

    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO2) {
        IedServer_updateUTCTimeAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2_stVal, value);
    }

    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO3) {
        IedServer_updateUTCTimeAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3_stVal, value);
    }

    if (parameter == IEDMODEL_GenericIO_GGIO1_SPCSO4) {
        IedServer_updateUTCTimeAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4_t, timeStamp);
        IedServer_updateAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4_stVal, value);
    }

    return CONTROL_RESULT_OK;
}

static void
connectionHandler (IedServer self, ClientConnection connection, bool connected, void* parameter)
{
    (void) self;
    (void) connection;
    (void) parameter;

    if (connected)
        printf("Connection opened\n");
    else
        printf("Connection closed\n");
}

static void
rcbEventHandler(void* parameter, ReportControlBlock* rcb, ClientConnection connection, IedServer_RCBEventType event, const char* parameterName, MmsDataAccessError serviceError)
{
    (void) parameter;
    (void) connection;

    printf("RCB: %s event: %i\n", ReportControlBlock_getName(rcb), event);

    if ((event == RCB_EVENT_SET_PARAMETER) || (event == RCB_EVENT_GET_PARAMETER))
    {
        printf("  param:  %s\n", parameterName);
        printf("  result: %i\n", serviceError);
    }

    if (event == RCB_EVENT_ENABLE)
    {
        char* rptId = ReportControlBlock_getRptID(rcb);
        printf("   rptID:  %s\n", rptId);
        char* dataSet = ReportControlBlock_getDataSet(rcb);
        printf("   datSet: %s\n", dataSet);

        free(rptId);
        free(dataSet);
    }
}

static uint8_t*
readStdinToBuffer(size_t* outSize)
{
    size_t capacity = 4096;
    size_t size = 0;
    uint8_t* buffer = (uint8_t*) malloc(capacity);

    if (buffer == NULL) {
        *outSize = 0;
        return NULL;
    }

    for (;;) {
        if (size == capacity) {
            if (capacity >= SDFUZZ_MAX_STDIN_SIZE)
                break;

            size_t newCapacity = capacity * 2;

            if (newCapacity > SDFUZZ_MAX_STDIN_SIZE)
                newCapacity = SDFUZZ_MAX_STDIN_SIZE;

            uint8_t* newBuffer = (uint8_t*) realloc(buffer, newCapacity);

            if (newBuffer == NULL)
                break;

            buffer = newBuffer;
            capacity = newCapacity;
        }

        ssize_t bytesRead = read(STDIN_FILENO, buffer + size, capacity - size);

        if (bytesRead > 0) {
            size += (size_t) bytesRead;
            continue;
        }

        if (bytesRead == 0)
            break;

        if (errno == EINTR)
            continue;

        break;
    }

    *outSize = size;
    return buffer;
}

static void
updateAnalogValuesOnce(float* t)
{
    uint64_t timestamp = Hal_getTimeInMs();

    *t += 0.1f;

    float an1 = sinf(*t);
    float an2 = sinf(*t + 1.f);
    float an3 = sinf(*t + 2.f);
    float an4 = sinf(*t + 3.f);

    Timestamp iecTimestamp;

    Timestamp_clearFlags(&iecTimestamp);
    Timestamp_setTimeInMilliseconds(&iecTimestamp, timestamp);
    Timestamp_setLeapSecondKnown(&iecTimestamp, true);

    /* toggle clock-not-synchronized flag in timestamp */
    if (((int) *t % 2) == 0)
        Timestamp_setClockNotSynchronized(&iecTimestamp, true);

    IedServer_lockDataModel(iedServer);

    IedServer_updateTimestampAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn1_t, &iecTimestamp);
    IedServer_updateFloatAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn1_mag_f, an1);

    IedServer_updateTimestampAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn2_t, &iecTimestamp);
    IedServer_updateFloatAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn2_mag_f, an2);

    IedServer_updateTimestampAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn3_t, &iecTimestamp);
    IedServer_updateFloatAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn3_mag_f, an3);

    IedServer_updateTimestampAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn4_t, &iecTimestamp);
    IedServer_updateFloatAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn4_mag_f, an4);

    IedServer_unlockDataModel(iedServer);
}

static int
connectToLocalServer(int tcpPort)
{
    int fd = -1;

    for (int i = 0; i < SDFUZZ_CONNECT_RETRIES; i++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);

        if (fd < 0)
            return -1;

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 200000;

        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t) tcpPort);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == 0)
            return fd;

        close(fd);
        fd = -1;

        Thread_sleep(10);
    }

    return -1;
}

static void
sendTestcaseToServer(int tcpPort, const uint8_t* data, size_t size)
{
    if (data == NULL || size == 0)
        return;

    int fd = connectToLocalServer(tcpPort);

    if (fd < 0)
        return;

    size_t offset = 0;

    while (offset < size) {
        ssize_t written = send(fd, data + offset, size - offset, MSG_NOSIGNAL);

        if (written > 0) {
            offset += (size_t) written;
            continue;
        }

        if (written < 0 && errno == EINTR)
            continue;

        break;
    }

    (void) shutdown(fd, SHUT_WR);

    /* Drain briefly so the server can complete response-side code paths. */
    uint8_t drain[1024];
    for (;;) {
        ssize_t r = recv(fd, drain, sizeof(drain), 0);

        if (r > 0)
            continue;

        if (r < 0 && errno == EINTR)
            continue;

        break;
    }

    close(fd);
}

int
main(int argc, char** argv)
{
    int tcpPort = 102;

    if (argc > 1) {
        tcpPort = atoi(argv[1]);
    }

    size_t testcaseSize = 0;
    uint8_t* testcase = readStdinToBuffer(&testcaseSize);

    printf("Using libIEC61850 version %s\n", LibIEC61850_getVersionString());

    /* Create new server configuration object */
    IedServerConfig config = IedServerConfig_create();

    /* Set buffer size for buffered report control blocks to 200000 bytes */
    IedServerConfig_setReportBufferSize(config, 200000);

    /* Set stack compliance to a specific edition of the standard (WARNING: data model has also to be checked for compliance) */
    IedServerConfig_setEdition(config, IEC_61850_EDITION_2);

    /* Set the base path for the MMS file services */
    IedServerConfig_setFileServiceBasePath(config, "./vmd-filestore/");

    /* disable MMS file service */
    IedServerConfig_enableFileService(config, false);

    /* enable dynamic data set service */
    IedServerConfig_enableDynamicDataSetService(config, true);

    /* disable log service */
    IedServerConfig_enableLogService(config, false);

    /* set maximum number of clients */
    IedServerConfig_setMaxMmsConnections(config, 2);

    /* Create a new IEC 61850 server instance */
    iedServer = IedServer_createWithConfig(&iedModel, NULL, config);

    /* configuration object is no longer required */
    IedServerConfig_destroy(config);

    /* set the identity values for MMS identify service */
    IedServer_setServerIdentity(iedServer, "MZ", "basic io", "1.6.0");

    /* Install handler for operate command */
    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO1);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO2);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO3);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO4);

    IedServer_setConnectionIndicationHandler(iedServer, (IedConnectionIndicationHandler) connectionHandler, NULL);

    IedServer_setRCBEventHandler(iedServer, rcbEventHandler, NULL);

    /* By default access to variables with FC=DC and FC=CF is not allowed.
     * This allow to write to simpleIOGenericIO/GGIO1.NamPlt.vendor variable used
     * by iec61850_client_example1.
     */
    IedServer_setWriteAccessPolicy(iedServer, IEC61850_FC_DC, ACCESS_POLICY_ALLOW);

    /* MMS server will be instructed to start listening for client connections. */
    IedServer_start(iedServer, tcpPort);

    if (!IedServer_isRunning(iedServer))
    {
        printf("Starting server failed (maybe need root permissions or another server is already using the port)! Exit.\n");
        IedServer_destroy(iedServer);
        free(testcase);
        exit(-1);
    }

    running = 1;

    signal(SIGINT, sigint_handler);

    float t = 0.f;

    for (int i = 0; running && i < SDFUZZ_PRE_SEND_TICKS; i++) {
        updateAnalogValuesOnce(&t);
        Thread_sleep(10);
    }

    sendTestcaseToServer(tcpPort, testcase, testcaseSize);

    for (int i = 0; running && i < SDFUZZ_POST_SEND_TICKS; i++) {
        updateAnalogValuesOnce(&t);
        Thread_sleep(SDFUZZ_POST_SEND_SLEEP_MS / SDFUZZ_POST_SEND_TICKS);
    }

    /* stop MMS server - close TCP server socket and all client sockets */
    IedServer_stop(iedServer);

    /* Cleanup - free all resources */
    IedServer_destroy(iedServer);

    free(testcase);

    return 0;
} /* main() */
