#include "crypto.h"
#include "policy.h"
#include "protocol.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

typedef SOCKET lab_socket_t;

#define LAB_INVALID_SOCKET INVALID_SOCKET
#define LAB_CLOSE_SOCKET closesocket

#else

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>

typedef int lab_socket_t;

#define LAB_INVALID_SOCKET (-1)
#define LAB_CLOSE_SOCKET close

#endif


//so that find_agent can call it
static int cmd_discover(int timeout_sec);


typedef struct {
    char agent_id[LAB_MAX_HOSTNAME];
    char hostname[LAB_MAX_HOSTNAME];
    char ip[64];
    uint16_t port;
    uint64_t last_seen;
} discovered_agent_t;


#define MAX_AGENTS 32

static discovered_agent_t g_agents[MAX_AGENTS];
static int g_agent_count = 0;

static uint8_t g_hmac_key[LAB_HMAC_KEY_DEFAULT_LEN];
static uint64_t g_seq = 1;


/* ------------------------------------------------------------------------- */
/* Socket initialization                                                     */
/* ------------------------------------------------------------------------- */

static int ws_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}


static void ws_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}


/* ------------------------------------------------------------------------- */
/* TCP                                                                       */
/* ------------------------------------------------------------------------- */

static lab_socket_t tcp_connect(const char *ip, uint16_t port)
{
    lab_socket_t s;
    struct sockaddr_in addr;

#ifdef _WIN32
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    s = socket(AF_INET, SOCK_STREAM, 0);
#endif

    if (s == LAB_INVALID_SOCKET)
        return LAB_INVALID_SOCKET;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        LAB_CLOSE_SOCKET(s);
        return LAB_INVALID_SOCKET;
    }

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LAB_CLOSE_SOCKET(s);
        return LAB_INVALID_SOCKET;
    }

    return s;
}


/* Send exactly len bytes. */
static int send_all(lab_socket_t sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
#ifdef _WIN32
        int n = send(
            sock,
            (const char *)buf + sent,
            (int)(len - sent),
            0
        );
#else
        ssize_t n = send(
            sock,
            buf + sent,
            len - sent,
            0
        );
#endif

        if (n <= 0) {
#ifndef _WIN32
            if (errno == EINTR)
                continue;
#endif
            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}


/*
 * Read enough bytes for a complete protocol message.
 *
 * Unix/TCP sockets are streams, so one recv() is NOT guaranteed to contain
 * an entire message.
 */
static int recv_all(lab_socket_t sock, uint8_t *buf, size_t len)
{
    size_t received = 0;

    while (received < len) {
#ifdef _WIN32
        int n = recv(
            sock,
            (char *)buf + received,
            (int)(len - received),
            0
        );
#else
        ssize_t n = recv(
            sock,
            buf + received,
            len - received,
            0
        );
#endif

        if (n <= 0) {
#ifndef _WIN32
            if (errno == EINTR)
                continue;
#endif
            return -1;
        }

        received += (size_t)n;
    }

    return 0;
}


/* ------------------------------------------------------------------------- */
/* Protocol                                                                   */
/* ------------------------------------------------------------------------- */

static int send_msg(lab_socket_t sock,uint16_t type,const uint8_t *payload,uint32_t plen){lab_msg_header_t hdr;lab_header_init(&hdr,type,g_seq++,NULL,plen);lab_header_sign(&hdr,payload,g_hmac_key,sizeof(g_hmac_key));if(send_all(sock,(const uint8_t *)&hdr,sizeof(hdr))!=0)return -1;if(plen>0&&send_all(sock,payload,plen)!=0)return -1;return 0;}

static int recv_msg(
    lab_socket_t sock,
    lab_msg_header_t *hdr,
    uint8_t *payload,
    size_t cap)
{
    uint8_t buf[LAB_MAX_PAYLOAD + 256];
    const uint8_t *pl;

    /*
     * First receive the fixed-size protocol header.
     */
    if (recv_all(
            sock,
            buf,
            sizeof(lab_msg_header_t)) != 0)
        return -1;

    /*
     * Header contains payload_len. Copy it out before receiving payload.
     */
    memcpy(
        hdr,
        buf,
        sizeof(lab_msg_header_t)
    );

    if (hdr->payload_len > LAB_MAX_PAYLOAD)
        return -1;

    if (hdr->payload_len > cap)
        return -1;

    /*
     * Receive the payload.
     */
    if (hdr->payload_len > 0) {
        if (recv_all(
                sock,
                buf + sizeof(lab_msg_header_t),
                hdr->payload_len) != 0)
            return -1;
    }

    /*
     * Validate the complete packed message.
     */
    if (lab_msg_unpack(
            buf,
            sizeof(lab_msg_header_t) + hdr->payload_len,
            hdr,
            &pl) != 0)
        return -1;

    if (lab_header_verify(
            hdr,
            pl,
            g_hmac_key,
            sizeof(g_hmac_key)) != 0)
        return -1;

    if (hdr->payload_len > 0)
        memcpy(
            payload,
            pl,
            hdr->payload_len
        );

    return (int)hdr->payload_len;
}


/* ------------------------------------------------------------------------- */
/* Agent discovery                                                           */
/* ------------------------------------------------------------------------- */

static void upsert_agent(
    const lab_announce_t *ann,
    const char *ip)
{
    int i;

    for (i = 0; i < g_agent_count; i++) {
        if (strcmp(
                g_agents[i].agent_id,
                ann->agent_id) == 0) {

            snprintf(
                g_agents[i].ip,
                sizeof(g_agents[i].ip),
                "%s",
                ip
            );

            g_agents[i].port = ann->tcp_port;
            g_agents[i].last_seen = lab_monotonic_sec();

            return;
        }
    }

    if (g_agent_count >= MAX_AGENTS)
        return;

    snprintf(
        g_agents[g_agent_count].agent_id,
        sizeof(g_agents[g_agent_count].agent_id),
        "%s",
        ann->agent_id
    );

    snprintf(
        g_agents[g_agent_count].hostname,
        sizeof(g_agents[g_agent_count].hostname),
        "%s",
        ann->hostname
    );

    snprintf(
        g_agents[g_agent_count].ip,
        sizeof(g_agents[g_agent_count].ip),
        "%s",
        ip
    );

    g_agents[g_agent_count].port = ann->tcp_port;
    g_agents[g_agent_count].last_seen = lab_monotonic_sec();

    g_agent_count++;
}


static int cmd_discover(int timeout_sec)
{
    lab_socket_t udp;
    struct sockaddr_in broadcast;
    lab_msg_header_t hdr;
    uint8_t buf[256];
    size_t outlen;
    int i;

#ifdef _WIN32
    udp = socket(
        AF_INET,
        SOCK_DGRAM,
        IPPROTO_UDP
    );
#else
    udp = socket(
        AF_INET,
        SOCK_DGRAM,
        0
    );
#endif

    if (udp == LAB_INVALID_SOCKET)
        return -1;

    {
        int yes = 1;

        setsockopt(
            udp,
            SOL_SOCKET,
            SO_BROADCAST,
            (const char *)&yes,
            sizeof(yes)
        );

#ifdef _WIN32

        DWORD tv = (DWORD)(timeout_sec * 1000);

        setsockopt(
            udp,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (const char *)&tv,
            sizeof(tv)
        );

#else

        struct timeval tv;

        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        setsockopt(
            udp,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv,
            sizeof(tv)
        );

#endif
    }

    lab_header_init(
        &hdr,
        LAB_MSG_DISCOVER,
        g_seq++,
        NULL,
        0
    );

    lab_header_sign(
        &hdr,
        (const uint8_t *)"",
        g_hmac_key,
        sizeof(g_hmac_key)
    );

    if (lab_msg_pack(
            buf,
            sizeof(buf),
            &hdr,
            NULL,
            &outlen) != 0) {

        LAB_CLOSE_SOCKET(udp);
        return -1;
    }

    memset(&broadcast, 0, sizeof(broadcast));

    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(LAB_UDP_DISCOVERY);
    broadcast.sin_addr.s_addr = INADDR_BROADCAST;

    for (i = 0; i < 3; i++) {
#ifdef _WIN32
        sendto(
            udp,
            (const char *)buf,
            (int)outlen,
            0,
            (struct sockaddr *)&broadcast,
            sizeof(broadcast)
        );
#else
        sendto(
            udp,
            buf,
            outlen,
            0,
            (struct sockaddr *)&broadcast,
            sizeof(broadcast)
        );
#endif
    }

    while (1) {
        uint8_t rbuf[512];
        struct sockaddr_in from;

#ifdef _WIN32
        int fromlen = sizeof(from);

        int n = recvfrom(
            udp,
            (char *)rbuf,
            sizeof(rbuf),
            0,
            (struct sockaddr *)&from,
            &fromlen
        );
#else
        socklen_t fromlen = sizeof(from);

        ssize_t n = recvfrom(
            udp,
            rbuf,
            sizeof(rbuf),
            0,
            (struct sockaddr *)&from,
            &fromlen
        );
#endif

        lab_msg_header_t rhdr;
        const uint8_t *payload;
        char ip[64];

        if (n <= 0)
            break;

        if (lab_msg_unpack(
                rbuf,
                (size_t)n,
                &rhdr,
                &payload) != 0)
            continue;

        if (rhdr.type != LAB_MSG_ANNOUNCE)
            continue;

        if (lab_header_verify(
                &rhdr,
                payload,
                g_hmac_key,
                sizeof(g_hmac_key)) != 0)
            continue;

        if (rhdr.payload_len < sizeof(lab_announce_t))
            continue;

        if (!inet_ntop(
                AF_INET,
                &from.sin_addr,
                ip,
                sizeof(ip)))
            continue;

        upsert_agent(
            (const lab_announce_t *)payload,
            ip
        );
    }

    LAB_CLOSE_SOCKET(udp);

    printf(
        "Agentes descobertos: %d\n",
        g_agent_count
    );

    for (i = 0; i < g_agent_count; i++) {
        printf(
            "  [%s] %s @ %s:%u\n",
            g_agents[i].agent_id,
            g_agents[i].hostname,
            g_agents[i].ip,
            g_agents[i].port
        );
    }

    return 0;
}


/* ------------------------------------------------------------------------- */
/* Agent lookup                                                              */
/* ------------------------------------------------------------------------- */


static discovered_agent_t *find_agent(const char *id)
{
int i;
static discovered_agent_t direct_agent;

/* Check agents discovered in this process. */
for (i = 0; i < g_agent_count; i++) {
    if (strcmp(g_agents[i].agent_id, id) == 0 ||
        strcmp(g_agents[i].hostname, id) == 0 ||
        strcmp(g_agents[i].ip, id) == 0) {
        return &g_agents[i];
    }
}

/*
 * Allow direct IP targets without discovery.
 */
{
    struct in_addr address;

    if (inet_pton(AF_INET, id, &address) == 1) {
        memset(&direct_agent, 0, sizeof(direct_agent));

        snprintf(
            direct_agent.agent_id,
            sizeof(direct_agent.agent_id),
            "%s",
            id
        );

        snprintf(
            direct_agent.hostname,
            sizeof(direct_agent.hostname),
            "%s",
            id
        );

        snprintf(
            direct_agent.ip,
            sizeof(direct_agent.ip),
            "%s",
            id
        );

        direct_agent.port = LAB_TCP_PORT;

        return &direct_agent;
    }
}

/*
 * No cached agent. Run discovery automatically.
 * This makes commands such as:
 *
 *   labadmin push TheYautja default.json
 *
 * work without requiring a separate "discover" command.
 */
if (cmd_discover(3) != 0)
    return NULL;

for (i = 0; i < g_agent_count; i++) {
    if (strcmp(g_agents[i].agent_id, id) == 0 ||
        strcmp(g_agents[i].hostname, id) == 0 ||
        strcmp(g_agents[i].ip, id) == 0) {
        return &g_agents[i];
    }
}

return NULL;

}




/* ------------------------------------------------------------------------- */
/* Push                                                                      */
/* ------------------------------------------------------------------------- */

static int cmd_push(
    const char *target,
    const char *policy_file)
{
    discovered_agent_t *agent;
    FILE *f;
    char json[LAB_MAX_PAYLOAD];
    lab_policy_t policy;
    lab_sealed_policy_t sealed;
    size_t n;
    lab_socket_t sock;
    lab_msg_header_t rhdr;
    uint8_t payload[64];

    agent = find_agent(target);

    if (!agent) {
        fprintf(
            stderr,
            "Agente nao encontrado: %s (use discover)\n",
            target
        );
        return -1;
    }

    f = fopen(policy_file, "r");

    if (!f) {
        fprintf(
            stderr,
            "Politica nao encontrada: %s\n",
            policy_file
        );
        return -1;
    }

    n = fread(
        json,
        1,
        sizeof(json) - 1,
        f
    );

    json[n] = '\0';

    fclose(f);

    if (lab_policy_from_json(
            &policy,
            json) != 0) {

        fprintf(
            stderr,
            "JSON de politica invalido\n"
        );

        return -1;
    }

    policy.issued_at = lab_now_unix();
    policy.valid_until = lab_now_unix() + 7 * 24 * 3600;
    policy.seq = lab_now_unix();

    if (lab_policy_seal(
            &sealed,
            &policy,
            g_hmac_key,
            sizeof(g_hmac_key)) != 0) {

        fprintf(
            stderr,
            "Falha ao assinar politica\n"
        );

        return -1;
    }

    sock = tcp_connect(
        agent->ip,
        agent->port
    );

    if (sock == LAB_INVALID_SOCKET) {
        fprintf(
            stderr,
            "Falha ao conectar em %s:%u\n",
            agent->ip,
            agent->port
        );

        return -1;
    }

    if (send_msg(
            sock,
            LAB_MSG_PUSH_POLICY,
            (uint8_t *)&sealed,
            sizeof(sealed)) != 0) {

        LAB_CLOSE_SOCKET(sock);
        return -1;
    }

    if (recv_msg(
            sock,
            &rhdr,
            payload,
            sizeof(payload)) >= 0 &&
        rhdr.type == LAB_MSG_ACK) {

        printf(
            "Politica enviada para %s com sucesso (seq=%llu)\n",
            agent->agent_id,
            (unsigned long long)policy.seq
        );

    } else {

        printf("Resposta inesperada do agente %s: type=%u payload_len=%u\n", agent->agent_id, rhdr.type, rhdr.payload_len);
    }

    LAB_CLOSE_SOCKET(sock);

    return 0;
}


/* ------------------------------------------------------------------------- */
/* Status                                                                    */
/* ------------------------------------------------------------------------- */

static int cmd_status(const char *target)
{
    discovered_agent_t *agent = find_agent(target);
    lab_socket_t sock;
    lab_msg_header_t rhdr;
    lab_status_t status;

    if (!agent) {
        fprintf(
            stderr,
            "Agente nao encontrado: %s\n",
            target
        );
        return -1;
    }

    sock = tcp_connect(
        agent->ip,
        agent->port
    );

    if (sock == LAB_INVALID_SOCKET)
        return -1;

    if (send_msg(
            sock,
            LAB_MSG_GET_STATUS,
            NULL,
            0) != 0) {

        LAB_CLOSE_SOCKET(sock);
        return -1;
    }

    if (recv_msg(
            sock,
            &rhdr,
            (uint8_t *)&status,
            sizeof(status)) >= 0 &&
        rhdr.type == LAB_MSG_STATUS_REPLY) {

        printf(
            "Agente: %s (%s)\n",
            status.agent_id,
            status.hostname
        );

        printf(
            "Perfil ativo: %s\n",
            status.active_profile
        );

        printf(
            "Status: %u | Policy seq: %llu | Uptime: %llu s\n",
            status.status,
            (unsigned long long)status.last_policy_seq,
            (unsigned long long)status.uptime_sec
        );
    }

    LAB_CLOSE_SOCKET(sock);

    return 0;
}


/* ------------------------------------------------------------------------- */
/* Switch                                                                    */
/* ------------------------------------------------------------------------- */

static int cmd_switch(
    const char *target,
    const char *profile)
{
    discovered_agent_t *agent = find_agent(target);
    lab_socket_t sock;
    lab_msg_header_t rhdr;
    uint8_t payload[64];

    if (!agent)
        return -1;

    sock = tcp_connect(
        agent->ip,
        agent->port
    );

    if (sock == LAB_INVALID_SOCKET)
        return -1;

    if (send_msg(
            sock,
            LAB_MSG_SWITCH_PROFILE,
            (const uint8_t *)profile,
            (uint32_t)strlen(profile)) != 0) {

        LAB_CLOSE_SOCKET(sock);
        return -1;
    }

    if (recv_msg(
            sock,
            &rhdr,
            payload,
            sizeof(payload)) < 0) {

        LAB_CLOSE_SOCKET(sock);
        return -1;
    }

    printf(
        "Perfil alterado para %s em %s\n",
        profile,
        agent->agent_id
    );

    LAB_CLOSE_SOCKET(sock);

    return 0;
}


/* ------------------------------------------------------------------------- */
/* Reset                                                                     */
/* ------------------------------------------------------------------------- */

static int cmd_reset(const char *target)
{
    discovered_agent_t *agent = find_agent(target);
    lab_socket_t sock;
    lab_msg_header_t rhdr;
    uint8_t payload[64];

    if (!agent)
        return -1;

    sock = tcp_connect(
        agent->ip,
        agent->port
    );

    if (sock == LAB_INVALID_SOCKET)
        return -1;

    if (send_msg(
            sock,
            LAB_MSG_TRIGGER_RESET,
            NULL,
            0) != 0) {

        LAB_CLOSE_SOCKET(sock);
        return -1;
    }

    if (recv_msg(
            sock,
            &rhdr,
            payload,
            sizeof(payload)) < 0) {

        LAB_CLOSE_SOCKET(sock);
        return -1;
    }

    printf(
        "Reset disparado em %s\n",
        agent->agent_id
    );

    LAB_CLOSE_SOCKET(sock);

    return 0;
}


/* ------------------------------------------------------------------------- */
/* CLI                                                                       */
/* ------------------------------------------------------------------------- */

static void usage(const char *prog)
{
    printf(
        "LabAdmin — Gestor de Agentes de Laboratorio\n\n"
        "Uso:\n"
        "  %s discover [--timeout N]\n"
        "  %s push <agente> <policy.json>\n"
        "  %s status <agente>\n"
        "  %s switch <agente> <perfil>\n"
        "  %s reset <agente>\n"
        "  %s add <id> <ip> [porta]\n"
        "\nOpcoes:\n"
        "  --key <path>   Chave HMAC compartilhada "
        "(default: keys/shared.key)\n",
        prog,
        prog,
        prog,
        prog,
        prog,
        prog
    );
}


static int cmd_add(
    const char *id,
    const char *ip,
    uint16_t port)
{
    if (g_agent_count >= MAX_AGENTS)
        return -1;

    snprintf(
        g_agents[g_agent_count].agent_id,
        sizeof(g_agents[g_agent_count].agent_id),
        "%s",
        id
    );

    snprintf(
        g_agents[g_agent_count].hostname,
        sizeof(g_agents[g_agent_count].hostname),
        "%s",
        id
    );

    snprintf(
        g_agents[g_agent_count].ip,
        sizeof(g_agents[g_agent_count].ip),
        "%s",
        ip
    );

    g_agents[g_agent_count].port = port;
    g_agents[g_agent_count].last_seen = lab_monotonic_sec();

    g_agent_count++;

    printf(
        "Agente adicionado: %s @ %s:%u\n",
        id,
        ip,
        port
    );

    return 0;
}


int main(int argc, char **argv)
{
    const char *key_path = "keys/shared.key";
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 &&
            i + 1 < argc) {

            key_path = argv[++i];
        }
    }

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (lab_load_key_file(
            g_hmac_key,
            sizeof(g_hmac_key),
            key_path) != 0) {

        fprintf(
            stderr,
            "Chave nao encontrada: %s\n",
            key_path
        );

        fprintf(
            stderr,
            "Execute o gerador de chaves apropriado para sua plataforma.\n"
        );

        return 1;
    }

    if (ws_init() != 0) {
        fprintf(
            stderr,
            "Falha ao inicializar sockets\n"
        );
        return 1;
    }

    if (strcmp(argv[1], "discover") == 0) {

        int timeout = 3;

        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--timeout") == 0 &&
                i + 1 < argc) {

                timeout = atoi(argv[++i]);
            }
        }

        cmd_discover(timeout);

    } else if (
        strcmp(argv[1], "push") == 0 &&
        argc >= 4) {

        cmd_push(
            argv[2],
            argv[3]
        );

    } else if (
        strcmp(argv[1], "status") == 0 &&
        argc >= 3) {

        cmd_status(argv[2]);

    } else if (
        strcmp(argv[1], "switch") == 0 &&
        argc >= 4) {

        cmd_switch(
            argv[2],
            argv[3]
        );

    } else if (
        strcmp(argv[1], "reset") == 0 &&
        argc >= 3) {

        cmd_reset(argv[2]);

    } else if (
        strcmp(argv[1], "add") == 0 &&
        argc >= 4) {

        uint16_t port = LAB_TCP_PORT;

        if (argc >= 5)
            port = (uint16_t)atoi(argv[4]);

        cmd_add(
            argv[2],
            argv[3],
            port
        );

    } else {

        usage(argv[0]);
        ws_cleanup();
        return 1;
    }

    ws_cleanup();

    return 0;
}

