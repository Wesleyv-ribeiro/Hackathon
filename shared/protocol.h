#ifndef LAB_PROTOCOL_H
#define LAB_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define LAB_MAGIC           0x4C414241u  /* "LABA" */
#define LAB_PROTOCOL_VER    1
#define LAB_TCP_PORT        7800
#define LAB_UDP_DISCOVERY   7801
#define LAB_IPC_PIPE_NAME   "\\\\.\\pipe\\labagent"
#define LAB_IPC_SOCK_PATH   "/run/labagent/agent.sock"

#define LAB_HMAC_SIZE       32
#define LAB_NONCE_SIZE      16
#define LAB_MAX_PAYLOAD     (65536 + 256)
#define LAB_MAX_HOSTNAME    128
#define LAB_MAX_PROFILE_ID  64
#define LAB_MAX_APPS        32
#define LAB_MAX_APP_NAME    128
#define LAB_MAX_RESET_DIRS  16
#define LAB_MAX_DIR_PATH    260

enum lab_msg_type {
    LAB_MSG_DISCOVER       = 0x01,
    LAB_MSG_ANNOUNCE       = 0x02,
    LAB_MSG_HEARTBEAT      = 0x03,
    LAB_MSG_PUSH_POLICY    = 0x10,
    LAB_MSG_SWITCH_PROFILE = 0x11,
    LAB_MSG_TRIGGER_RESET  = 0x12,
    LAB_MSG_GET_STATUS     = 0x20,
    LAB_MSG_STATUS_REPLY   = 0x21,
    LAB_MSG_ACK            = 0x30,
    LAB_MSG_ERROR          = 0xFF
};

enum lab_agent_status {
    LAB_STATUS_IDLE      = 0,
    LAB_STATUS_BUSY      = 1,
    LAB_STATUS_RESETTING = 2,
    LAB_STATUS_OFFLINE   = 3
};

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint64_t seq;
    uint64_t timestamp;
    uint32_t payload_len;
    uint8_t  nonce[LAB_NONCE_SIZE];
    uint8_t  hmac[LAB_HMAC_SIZE];
} lab_msg_header_t;
#pragma pack(pop)

typedef struct {
    char     agent_id[LAB_MAX_HOSTNAME];
    char     hostname[LAB_MAX_HOSTNAME];
    char     active_profile[LAB_MAX_PROFILE_ID];
    uint8_t  status;
    uint64_t last_policy_seq;
    uint64_t uptime_sec;
} lab_status_t;

typedef struct {
    char agent_id[LAB_MAX_HOSTNAME];
    char hostname[LAB_MAX_HOSTNAME];
    uint16_t tcp_port;
    uint8_t  pubkey_hash[LAB_HMAC_SIZE];
} lab_announce_t;

int lab_header_init(lab_msg_header_t *hdr, uint16_t type, uint64_t seq,
                    const uint8_t *nonce, uint32_t payload_len);
int lab_header_verify(const lab_msg_header_t *hdr, const uint8_t *payload,
                      const uint8_t *hmac_key, size_t hmac_key_len);
int lab_header_sign(lab_msg_header_t *hdr, const uint8_t *payload,
                    const uint8_t *hmac_key, size_t hmac_key_len);
int lab_msg_pack(uint8_t *buf, size_t buf_len, const lab_msg_header_t *hdr,
                 const uint8_t *payload, size_t *out_len);
int lab_msg_unpack(const uint8_t *buf, size_t buf_len, lab_msg_header_t *hdr,
                   const uint8_t **payload);

#endif /* LAB_PROTOCOL_H */
