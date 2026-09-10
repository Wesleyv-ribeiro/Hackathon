#include "network.h"
#include "crypto.h"
#include "audit.h"
#include "reset.h"
#include "state.h"
#include "protocol.h"
#include "policy.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

typedef SOCKET lab_socket_t;

#define LAB_INVALID_SOCKET INVALID_SOCKET
#define lab_close_socket closesocket

static lab_socket_t g_tcp_sock = INVALID_SOCKET;
static lab_socket_t g_udp_sock = INVALID_SOCKET;
static HANDLE g_net_thread = NULL;
static volatile int g_net_running = 0;

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int lab_socket_t;

#define LAB_INVALID_SOCKET (-1)
#define lab_close_socket close

static lab_socket_t g_tcp_sock = -1;
static lab_socket_t g_udp_sock = -1;
static pthread_t g_net_thread;
static volatile int g_net_running = 0;
static int g_net_thread_started = 0;

#endif


static int send_all(lab_socket_t sock, const uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total < len)
    {
#ifdef _WIN32
        int n = send(sock, (const char *)buf + total,
                     (int)(len - total), 0);
#else
        ssize_t n = send(sock, buf + total, len - total, 0);
#endif

        if (n <= 0)
            return -1;

        total += (size_t)n;
    }

    return 0;
}


static int send_reply(lab_socket_t client, uint16_t type,
                      const uint8_t *payload, uint32_t plen)
{
    lab_msg_header_t hdr;
    uint8_t buf[LAB_MAX_PAYLOAD + 256];
    size_t outlen;
    lab_agent_state_t *st = lab_state();

    lab_header_init(&hdr, type, ++st->msg_seq, NULL, plen);
    lab_header_sign(&hdr, payload, st->hmac_key, sizeof(st->hmac_key));

    if (lab_msg_pack(buf, sizeof(buf), &hdr, payload, &outlen) != 0)
        return -1;

    return send_all(client, buf, outlen);
}


int lab_network_handle_push(const uint8_t *payload, uint32_t len)
{
    lab_sealed_policy_t sealed;
    lab_policy_t policy;
    lab_agent_state_t *st = lab_state();

    if (len < sizeof(lab_sealed_policy_t))
        return -1;

    memcpy(&sealed, payload, sizeof(sealed));

{
        int rc = lab_policy_unseal(&policy, &sealed,
                               st->hmac_key,
                               sizeof(st->hmac_key));

        if (rc != 0)
        {
            lab_audit_log("POLICY_REJECT",
                        "unseal failed rc=%d len=%u seq=%llu",
                          rc,
                          len,
                          (unsigned long long)sealed.seq);
            return -1;
        }
    }

    if (st->policy_loaded && sealed.seq <= st->policy_seq)
    {
        lab_audit_log("POLICY_REJECT",
                      "stale_seq=%llu current=%llu",
                      (unsigned long long)sealed.seq,
                      (unsigned long long)st->policy_seq);
        return -1;
    }

    if (lab_policy_save_file(&sealed, lab_policy_path()) != 0) { lab_audit_log("POLICY_REJECT", "save_file failed"); return -1; }

    if (lab_state_apply_policy(&policy) != 0) { lab_audit_log("POLICY_REJECT", "apply_policy failed"); return -1; }

    return 0;
}


static int recv_all(lab_socket_t sock, uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total < len)
    {
#ifdef _WIN32
        int n = recv(sock,
                     (char *)buf + total,
                     (int)(len - total),
                     0);
#else
        ssize_t n = recv(sock,
                         buf + total,
                         len - total,
                         0);
#endif

        if (n <= 0)
            return -1;

        total += (size_t)n;
    }

    return 0;
}


static void handle_client(lab_socket_t client)
{
    lab_msg_header_t hdr;
    uint8_t *payload = NULL;
    lab_agent_state_t *st = lab_state();

    /*
     * TCP is a byte stream.
     * First receive exactly the fixed-size header.
     */
    if (recv_all(client,
                 (uint8_t *)&hdr,
                 sizeof(hdr)) != 0)
    {
        lab_audit_log("NET_REJECT", "failed to receive header");
        return;
    }

    /*
     * Validate the header before allocating/receiving payload.
     */
    if (hdr.magic != LAB_MAGIC ||
        hdr.version != LAB_PROTOCOL_VER ||
        hdr.payload_len > LAB_MAX_PAYLOAD)
    {
        lab_audit_log("NET_REJECT",
                      "invalid header magic=%08x version=%u payload_len=%u",
                      hdr.magic,
                      hdr.version,
                      hdr.payload_len);
        return;
    }

    /*
     * Receive exactly the payload declared by the header.
     */
    if (hdr.payload_len > 0)
    {
        payload = malloc(hdr.payload_len);

        if (!payload)
        {
            lab_audit_log("NET_REJECT",
                          "payload allocation failed len=%u",
                          hdr.payload_len);
            return;
        }

        if (recv_all(client,
                     payload,
                     hdr.payload_len) != 0)
        {
            lab_audit_log("NET_REJECT",
                          "failed to receive payload len=%u",
                          hdr.payload_len);
            free(payload);
            return;
        }
    }

    /*
     * Verify the HMAC over the complete message.
     */
    if (lab_header_verify(&hdr,
                          payload,
                          st->hmac_key,
                          sizeof(st->hmac_key)) != 0)
    {
        lab_audit_log("NET_REJECT",
                      "HMAC invalido seq=%llu",
                      (unsigned long long)hdr.seq);

        free(payload);
        return;
    }

    switch (hdr.type)
    {
    case LAB_MSG_PUSH_POLICY:
        if (lab_network_handle_push(payload,
                                    hdr.payload_len) == 0)
        {
            send_reply(client,
                       LAB_MSG_ACK,
                       NULL,
                       0);
        }
        else
        {
            send_reply(client,
                       LAB_MSG_ERROR,
                       (uint8_t *)"POLICY",
                       6);
        }
        break;

    case LAB_MSG_SWITCH_PROFILE:
        if (hdr.payload_len > 0)
        {
            char profile[LAB_MAX_PROFILE_ID];
            size_t plen = hdr.payload_len;

            if (plen >= sizeof(profile))
                plen = sizeof(profile) - 1;

            memcpy(profile, payload, plen);
            profile[plen] = '\0';

            lab_state_switch_profile(profile);
        }

        send_reply(client,
                   LAB_MSG_ACK,
                   NULL,
                   0);
        break;

    case LAB_MSG_TRIGGER_RESET:
        lab_reset_run(lab_state_active_profile());

        send_reply(client,
                   LAB_MSG_ACK,
                   NULL,
                   0);
        break;

    case LAB_MSG_GET_STATUS:
    {
        lab_status_t status;

        memset(&status, 0, sizeof(status));

        snprintf(status.agent_id,
                 sizeof(status.agent_id),
                 "%s",
                 st->agent_id);

        snprintf(status.hostname,
                 sizeof(status.hostname),
                 "%s",
                 st->hostname);

        snprintf(status.active_profile,
                 sizeof(status.active_profile),
                 "%s",
                 st->active_profile);

        status.status = st->agent_status;
        status.last_policy_seq = st->policy_seq;
        status.uptime_sec =
            lab_monotonic_sec() - st->start_time;

        send_reply(client,
                   LAB_MSG_STATUS_REPLY,
                   (uint8_t *)&status,
                   sizeof(status));
        break;
    }

    default:
        send_reply(client,
                   LAB_MSG_ERROR,
                   (uint8_t *)"UNKNOWN",
                   7);
        break;
    }

    free(payload);
}


static void send_announce(lab_socket_t udp,
                          struct sockaddr_in *from)
{
    lab_announce_t ann;
    lab_msg_header_t hdr;
    uint8_t buf[512];
    size_t outlen;
    lab_agent_state_t *st = lab_state();

    memset(&ann, 0, sizeof(ann));

    snprintf(ann.agent_id,
             sizeof(ann.agent_id),
             "%s",
             st->agent_id);

    snprintf(ann.hostname,
             sizeof(ann.hostname),
             "%s",
             st->hostname);

    ann.tcp_port = LAB_TCP_PORT;

    lab_sha256(st->hmac_key,
               sizeof(st->hmac_key),
               ann.pubkey_hash);

    lab_header_init(&hdr,
                    LAB_MSG_ANNOUNCE,
                    ++st->msg_seq,
                    NULL,
                    sizeof(ann));

    lab_header_sign(&hdr,
                    (uint8_t *)&ann,
                    st->hmac_key,
                    sizeof(st->hmac_key));

    if (lab_msg_pack(buf,
                     sizeof(buf),
                     &hdr,
                     (uint8_t *)&ann,
                     &outlen) != 0)
        return;

#ifdef _WIN32

    sendto(udp,
           (const char *)buf,
           (int)outlen,
           0,
           (struct sockaddr *)from,
           sizeof(*from));

#else

    sendto(udp,
           buf,
           outlen,
           0,
           (struct sockaddr *)from,
           sizeof(*from));

#endif
}


#ifdef _WIN32

static DWORD WINAPI network_thread(LPVOID unused)

#else

static void *network_thread(void *unused)

#endif
{
    (void)unused;

    while (g_net_running)
    {
        fd_set rfds;
        struct timeval tv = {1, 0};

        FD_ZERO(&rfds);
        FD_SET(g_tcp_sock, &rfds);
        FD_SET(g_udp_sock, &rfds);

#ifdef _WIN32
        int result = select(0, &rfds, NULL, NULL, &tv);
#else
        int max_fd = g_tcp_sock > g_udp_sock
                   ? g_tcp_sock
                   : g_udp_sock;

        int result = select(max_fd + 1,
                            &rfds,
                            NULL,
                            NULL,
                            &tv);
#endif

        if (result <= 0)
            continue;

        if (FD_ISSET(g_udp_sock, &rfds))
        {
            uint8_t buf[512];
            struct sockaddr_in from;

#ifdef _WIN32
            int fromlen = sizeof(from);

            int n = recvfrom(
                g_udp_sock,
                (char *)buf,
                sizeof(buf),
                0,
                (struct sockaddr *)&from,
                &fromlen
            );
#else
            socklen_t fromlen = sizeof(from);

            ssize_t n = recvfrom(
                g_udp_sock,
                buf,
                sizeof(buf),
                0,
                (struct sockaddr *)&from,
                &fromlen
            );
#endif

            lab_msg_header_t hdr;
            const uint8_t *payload;

            if (n >= (int)sizeof(lab_msg_header_t) &&
                lab_msg_unpack(buf,
                               (size_t)n,
                               &hdr,
                               &payload) == 0 &&
                hdr.type == LAB_MSG_DISCOVER)
            {
                send_announce(g_udp_sock, &from);
            }
        }

        if (FD_ISSET(g_tcp_sock, &rfds))
        {
            lab_socket_t client =
                accept(g_tcp_sock, NULL, NULL);

            if (client != LAB_INVALID_SOCKET)
            {
                handle_client(client);
                lab_close_socket(client);
            }
        }
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}


int lab_network_start(void)
{
    struct sockaddr_in addr;
    lab_agent_state_t *st = lab_state();

#ifdef _WIN32

    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return -1;

#endif

    g_tcp_sock = socket(AF_INET,
                        SOCK_STREAM,
                        IPPROTO_TCP);

    g_udp_sock = socket(AF_INET,
                        SOCK_DGRAM,
                        IPPROTO_UDP);

    if (g_tcp_sock == LAB_INVALID_SOCKET ||
        g_udp_sock == LAB_INVALID_SOCKET)
    {
        fprintf(stderr, "[network] Failed to create TCP or UDP socket\n");
        lab_network_stop();
        return -1;
    }

    {
        int yes = 1;
        if (setsockopt(g_tcp_sock,
                       SOL_SOCKET,
                       SO_REUSEADDR,
#ifdef _WIN32
                       (const char *)&yes,
#else
                       &yes,
#endif
                       sizeof(yes)) != 0)
        {
            fprintf(stderr, "[network] Warning: failed to set SO_REUSEADDR on TCP socket\n");
        }
    }

    {
        int yes = 1;
        if (setsockopt(g_udp_sock,
                       SOL_SOCKET,
                       SO_REUSEADDR,
#ifdef _WIN32
                       (const char *)&yes,
#else
                       &yes,
#endif
                       sizeof(yes)) != 0)
        {
            fprintf(stderr, "[network] Warning: failed to set SO_REUSEADDR on UDP socket\n");
        }

        if (setsockopt(g_udp_sock,
                   SOL_SOCKET,
                   SO_BROADCAST,
#ifdef _WIN32
                   (const char *)&yes,
#else
                   &yes,
#endif
                   sizeof(yes)) != 0)
        {
            fprintf(stderr, "[network] Warning: failed to set SO_BROADCAST on UDP socket\n");
        }
    }

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LAB_TCP_PORT);

    if (bind(g_tcp_sock,
             (struct sockaddr *)&addr,
             sizeof(addr)) != 0)
    {
        lab_network_stop();
        return -1;
    }

    if (listen(g_tcp_sock, SOMAXCONN) != 0)
    {
        lab_network_stop();
        return -1;
    }

    addr.sin_port = htons(LAB_UDP_DISCOVERY);

    if (bind(g_udp_sock,
             (struct sockaddr *)&addr,
             sizeof(addr)) != 0)
    {
        lab_network_stop();
        return -1;
    }

    g_net_running = 1;

#ifdef _WIN32

    g_net_thread = CreateThread(
        NULL,
        0,
        network_thread,
        NULL,
        0,
        NULL
    );

    if (!g_net_thread)
    {
        g_net_running = 0;
        lab_network_stop();
        return -1;
    }

#else

    if (pthread_create(&g_net_thread,
                       NULL,
                       network_thread,
                       NULL) != 0)
    {
        g_net_running = 0;
        lab_network_stop();
        return -1;
    }

    g_net_thread_started = 1;

#endif

    lab_audit_log("NETWORK_START",
                  "tcp=%d udp=%d id=%s",
                  LAB_TCP_PORT,
                  LAB_UDP_DISCOVERY,
                  st->agent_id);

    return 0;
}


void lab_network_stop(void)
{
    g_net_running = 0;

#ifdef _WIN32

    if (g_net_thread)
    {
        WaitForSingleObject(g_net_thread, 5000);
        CloseHandle(g_net_thread);
        g_net_thread = NULL;
    }

#else

    if (g_net_thread_started)
    {
        pthread_join(g_net_thread, NULL);
        g_net_thread_started = 0;
    }

#endif

    if (g_tcp_sock != LAB_INVALID_SOCKET)
    {
        lab_close_socket(g_tcp_sock);
        g_tcp_sock = LAB_INVALID_SOCKET;
    }

    if (g_udp_sock != LAB_INVALID_SOCKET)
    {
        lab_close_socket(g_udp_sock);
        g_udp_sock = LAB_INVALID_SOCKET;
    }

#ifdef _WIN32
    WSACleanup();
#endif
}
