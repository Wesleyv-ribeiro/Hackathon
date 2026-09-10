#ifndef LAB_POLICY_H
#define LAB_POLICY_H

#include "protocol.h"
#include <stdint.h>
#include <stddef.h>
#include <protocol.h>

#define LAB_MAX_PROFILES    8
#define LAB_MAX_SCHEDULES   8

typedef struct {
    char name[LAB_MAX_PROFILE_ID];
    char blocked_apps[LAB_MAX_APPS][LAB_MAX_APP_NAME];
    int  blocked_count;
    char allowed_apps[LAB_MAX_APPS][LAB_MAX_APP_NAME];
    int  allowed_count;
    char reset_dirs[LAB_MAX_RESET_DIRS][LAB_MAX_DIR_PATH];
    int  reset_dir_count;
    int  block_install;
    int  block_registry;
} lab_profile_t;

typedef struct {
    char profile_id[LAB_MAX_PROFILE_ID];
    int  hour_start;
    int  minute_start;
    int  hour_end;
    int  minute_end;
    int  days_mask;  /* bit0=dom ... bit6=sab */
} lab_schedule_t;

typedef struct {
    uint32_t version;
    uint64_t issued_at;
    uint64_t valid_until;
    uint64_t seq;
    char     default_profile[LAB_MAX_PROFILE_ID];
    lab_profile_t profiles[LAB_MAX_PROFILES];
    int      profile_count;
    lab_schedule_t schedules[LAB_MAX_SCHEDULES];
    int      schedule_count;
    int      reset_on_logoff;
    int      reset_timeout_min;
} lab_policy_t;


typedef struct {
    uint32_t version;
    uint64_t issued_at;
    uint64_t valid_until;
    uint64_t seq;
    uint8_t  payload_hash[LAB_HMAC_SIZE];
    uint8_t  signature[LAB_HMAC_SIZE];
    char     json_payload[65536];
} lab_sealed_policy_t;


int  lab_policy_from_json(lab_policy_t *out, const char *json);
int  lab_policy_to_json(const lab_policy_t *policy, char *buf, size_t buf_len);
int  lab_policy_seal(lab_sealed_policy_t *sealed, const lab_policy_t *policy,
                     const uint8_t *sign_key, size_t sign_key_len);
int  lab_policy_unseal(lab_policy_t *out, const lab_sealed_policy_t *sealed,
                       const uint8_t *sign_key, size_t sign_key_len);
int  lab_policy_save_file(const lab_sealed_policy_t *sealed, const char *path);
int  lab_policy_load_file(lab_sealed_policy_t *sealed, const char *path);
const lab_profile_t *lab_policy_find_profile(const lab_policy_t *policy,
                                             const char *profile_id);
const char *lab_policy_profile_for_time(const lab_policy_t *policy);

#endif /* LAB_POLICY_H */
