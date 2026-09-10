#include "policy.h"
#include "crypto.h"
#include "util.h"
#include "third_party/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <io.h>
#else
#include <strings.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static int parse_time_hhmm(const char *s, int *hour, int *minute)
{
    if (!s || sscanf(s, "%d:%d", hour, minute) != 2)
        return -1;
    return 0;
}

static void parse_string_array(cJSON *arr, char dest[][LAB_MAX_APP_NAME],
                               int *count, int max)
{
    *count = 0;
    if (!cJSON_IsArray(arr))
        return;

    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (*count >= max)
            break;
        if (cJSON_IsString(item) && item->valuestring) {
            snprintf(dest[*count], LAB_MAX_APP_NAME, "%s", item->valuestring);
            (*count)++;
        }
    }
}

static void parse_dir_array(cJSON *arr, char dest[][LAB_MAX_DIR_PATH], int *count, int max)
{
    *count = 0;
    if (!cJSON_IsArray(arr))
        return;

    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (*count >= max)
            break;
        if (cJSON_IsString(item) && item->valuestring) {
            snprintf(dest[*count], LAB_MAX_DIR_PATH, "%s", item->valuestring);
            (*count)++;
        }
    }
}

int lab_policy_from_json(lab_policy_t *out, const char *json)
{
    cJSON *root = cJSON_Parse(json);
    cJSON *profiles, *schedules, *item;

    if (!out || !json || !root)
        return -1;

    memset(out, 0, sizeof(*out));
    {
        cJSON *v = cJSON_GetObjectItem(root, "version");
        cJSON *ia = cJSON_GetObjectItem(root, "issued_at");
        cJSON *vu = cJSON_GetObjectItem(root, "valid_until");
        cJSON *sq = cJSON_GetObjectItem(root, "seq");
        out->version = cJSON_IsNumber(v) ? (uint32_t)v->valuedouble : 1;
        out->issued_at = cJSON_IsNumber(ia) ? (uint64_t)ia->valuedouble : lab_now_unix();
        out->valid_until = cJSON_IsNumber(vu) ? (uint64_t)vu->valuedouble : lab_now_unix() + 604800;
        out->seq = cJSON_IsNumber(sq) ? (uint64_t)sq->valuedouble : 1;
    }

    {
        cJSON *dp = cJSON_GetObjectItem(root, "default_profile");
        if (cJSON_IsString(dp))
            snprintf(out->default_profile, sizeof(out->default_profile), "%s", dp->valuestring);
    }

    out->reset_on_logoff = cJSON_IsTrue(cJSON_GetObjectItem(root, "reset_on_logoff"));
    {
        cJSON *rt = cJSON_GetObjectItem(root, "reset_timeout_min");
        out->reset_timeout_min = cJSON_IsNumber(rt) ? rt->valueint : 15;
    }

    profiles = cJSON_GetObjectItem(root, "profiles");
    if (cJSON_IsArray(profiles)) {
        cJSON_ArrayForEach(item, profiles) {
            if (out->profile_count >= LAB_MAX_PROFILES)
                break;

            lab_profile_t *p = &out->profiles[out->profile_count];
            cJSON *name = cJSON_GetObjectItem(item, "name");
            if (cJSON_IsString(name))
                snprintf(p->name, sizeof(p->name), "%s", name->valuestring);

            parse_string_array(cJSON_GetObjectItem(item, "blocked_apps"),
                               p->blocked_apps, &p->blocked_count, LAB_MAX_APPS);
            parse_string_array(cJSON_GetObjectItem(item, "allowed_apps"),
                               p->allowed_apps, &p->allowed_count, LAB_MAX_APPS);
            parse_dir_array(cJSON_GetObjectItem(item, "reset_dirs"),
                            p->reset_dirs, &p->reset_dir_count, LAB_MAX_RESET_DIRS);

            p->block_install = cJSON_IsTrue(cJSON_GetObjectItem(item, "block_install"));
            p->block_registry = cJSON_IsTrue(cJSON_GetObjectItem(item, "block_registry"));
            out->profile_count++;
        }
    }

    schedules = cJSON_GetObjectItem(root, "schedules");
    if (cJSON_IsArray(schedules)) {
        cJSON_ArrayForEach(item, schedules) {
            if (out->schedule_count >= LAB_MAX_SCHEDULES)
                break;

            lab_schedule_t *s = &out->schedules[out->schedule_count];
            cJSON *pid = cJSON_GetObjectItem(item, "profile_id");
            cJSON *start = cJSON_GetObjectItem(item, "start");
            cJSON *end = cJSON_GetObjectItem(item, "end");
            cJSON *days = cJSON_GetObjectItem(item, "days");

            if (cJSON_IsString(pid))
                snprintf(s->profile_id, sizeof(s->profile_id), "%s", pid->valuestring);
            if (cJSON_IsString(start))
                parse_time_hhmm(start->valuestring, &s->hour_start, &s->minute_start);
            if (cJSON_IsString(end))
                parse_time_hhmm(end->valuestring, &s->hour_end, &s->minute_end);

            s->days_mask = 0;
            if (cJSON_IsArray(days)) {
                cJSON *d;
                cJSON_ArrayForEach(d, days) {
                    if (cJSON_IsNumber(d) && d->valueint >= 0 && d->valueint <= 6)
                        s->days_mask |= (1 << d->valueint);
                }
            }
            out->schedule_count++;
        }
    }

    cJSON_Delete(root);
    return 0;
}

int lab_policy_to_json(const lab_policy_t *policy, char *buf, size_t buf_len)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *profiles = cJSON_CreateArray();
    cJSON *schedules = cJSON_CreateArray();
    int i, j;

    if (!policy || !buf || !root)
        return -1;

    cJSON_AddNumberToObject(root, "version", policy->version);
    cJSON_AddNumberToObject(root, "issued_at", (double)policy->issued_at);
    cJSON_AddNumberToObject(root, "valid_until", (double)policy->valid_until);
    cJSON_AddNumberToObject(root, "seq", (double)policy->seq);
    cJSON_AddStringToObject(root, "default_profile", policy->default_profile);
    cJSON_AddBoolToObject(root, "reset_on_logoff", policy->reset_on_logoff ? 1 : 0);
    cJSON_AddNumberToObject(root, "reset_timeout_min", policy->reset_timeout_min);

    for (i = 0; i < policy->profile_count; i++) {
        const lab_profile_t *p = &policy->profiles[i];
        cJSON *prof = cJSON_CreateObject();
        cJSON *blocked = cJSON_CreateArray();
        cJSON *allowed = cJSON_CreateArray();
        cJSON *dirs = cJSON_CreateArray();

        cJSON_AddStringToObject(prof, "name", p->name);
        for (j = 0; j < p->blocked_count; j++)
            cJSON_AddItemToArray(blocked, cJSON_CreateString(p->blocked_apps[j]));
        for (j = 0; j < p->allowed_count; j++)
            cJSON_AddItemToArray(allowed, cJSON_CreateString(p->allowed_apps[j]));
        for (j = 0; j < p->reset_dir_count; j++)
            cJSON_AddItemToArray(dirs, cJSON_CreateString(p->reset_dirs[j]));

        cJSON_AddItemToObject(prof, "blocked_apps", blocked);
        cJSON_AddItemToObject(prof, "allowed_apps", allowed);
        cJSON_AddItemToObject(prof, "reset_dirs", dirs);
        cJSON_AddBoolToObject(prof, "block_install", p->block_install ? 1 : 0);
        cJSON_AddBoolToObject(prof, "block_registry", p->block_registry ? 1 : 0);
        cJSON_AddItemToArray(profiles, prof);
    }

    for (i = 0; i < policy->schedule_count; i++) {
        const lab_schedule_t *s = &policy->schedules[i];
        cJSON *sch = cJSON_CreateObject();
        cJSON *days = cJSON_CreateArray();
        char tbuf[8];
        int d;

        cJSON_AddStringToObject(sch, "profile_id", s->profile_id);
        snprintf(tbuf, sizeof(tbuf), "%02d:%02d", s->hour_start, s->minute_start);
        cJSON_AddStringToObject(sch, "start", tbuf);
        snprintf(tbuf, sizeof(tbuf), "%02d:%02d", s->hour_end, s->minute_end);
        cJSON_AddStringToObject(sch, "end", tbuf);

        for (d = 0; d <= 6; d++)
            if (s->days_mask & (1 << d))
                cJSON_AddItemToArray(days, cJSON_CreateNumber(d));

        cJSON_AddItemToObject(sch, "days", days);
        cJSON_AddItemToArray(schedules, sch);
    }

    cJSON_AddItemToObject(root, "profiles", profiles);
    cJSON_AddItemToObject(root, "schedules", schedules);

    {
        char *printed = cJSON_PrintUnformatted(root);
        if (!printed) {
            cJSON_Delete(root);
            return -1;
        }
        snprintf(buf, buf_len, "%s", printed);
        free(printed);
    }

    cJSON_Delete(root);
    return 0;
}

int lab_policy_seal(lab_sealed_policy_t *sealed, const lab_policy_t *policy,
                    const uint8_t *sign_key, size_t sign_key_len)
{
    if (!sealed || !policy || !sign_key)
        return -1;

    memset(sealed, 0, sizeof(*sealed));
    sealed->version = policy->version;
    sealed->issued_at = policy->issued_at;
    sealed->valid_until = policy->valid_until;
    sealed->seq = policy->seq;

    if (lab_policy_to_json(policy, sealed->json_payload,
                           LAB_MAX_PAYLOAD) != 0)
        return -1;

    if (lab_sha256((const uint8_t *)sealed->json_payload,
                   strlen(sealed->json_payload), sealed->payload_hash) != 0)
        return -1;

    return lab_hmac_sha256(sign_key, sign_key_len, sealed->payload_hash,
                           LAB_SHA256_SIZE, sealed->signature);
}

int lab_policy_unseal(lab_policy_t *out, const lab_sealed_policy_t *sealed,
                      const uint8_t *sign_key, size_t sign_key_len)
{
    uint8_t hash[LAB_SHA256_SIZE];
    uint8_t sig[LAB_SHA256_SIZE];

    if (!out || !sealed || !sign_key)
        return -1;

    if (lab_sha256((const uint8_t *)sealed->json_payload,
                   strlen(sealed->json_payload), hash) != 0)
        return -1;

    if (!lab_secure_compare(hash, sealed->payload_hash, LAB_SHA256_SIZE))
        return -1;

    if (lab_hmac_sha256(sign_key, sign_key_len, sealed->payload_hash,
                        LAB_SHA256_SIZE, sig) != 0)
        return -1;

    if (!lab_secure_compare(sig, sealed->signature, LAB_SHA256_SIZE))
        return -1;

    if (sealed->valid_until != 0 && sealed->valid_until < lab_now_unix())
        return -2;

    return lab_policy_from_json(out, sealed->json_payload);
}

int lab_policy_save_file(const lab_sealed_policy_t *sealed, const char *path)
{
    char tmp_path[512];
    FILE *f;

    if (!sealed || !path)
        return -1;

#ifdef _WIN32
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%lu", path,
             (unsigned long)GetCurrentProcessId());
#else
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%lu", path,
             (unsigned long)getpid());
#endif

    f = fopen(tmp_path, "wb");
    if (!f)
        return -1;
    if (fwrite(sealed, sizeof(*sealed), 1, f) != 1) {
        fclose(f);
        remove(tmp_path);
        return -1;
    }
    fflush(f);
#ifdef _WIN32
    FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(f)));
#else
    fsync(fileno(f));
#endif
    fclose(f);

#ifdef _WIN32
    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        remove(tmp_path);
        return -1;
    }
    {
        PSECURITY_DESCRIPTOR sd = NULL;
        PACL dacl = NULL;
        BOOL dacl_present = FALSE;
        BOOL dacl_defaulted = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &sd, NULL))
            return -1;
        if (!GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) ||
            !dacl_present) {
            LocalFree(sd);
            return -1;
        }
        if (SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                  NULL, NULL, dacl, NULL) != ERROR_SUCCESS) {
            LocalFree(sd);
            return -1;
        }
        LocalFree(sd);
    }
#else
    if (rename(tmp_path, path) != 0)
        return -1;
    chmod(path, S_IRUSR | S_IWUSR);
#endif
    return 0;
}

int lab_policy_load_file(lab_sealed_policy_t *sealed, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fread(sealed, sizeof(*sealed), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

const lab_profile_t *lab_policy_find_profile(const lab_policy_t *policy,
                                             const char *profile_id)
{
    int i;
    if (!policy || !profile_id)
        return NULL;

    for (i = 0; i < policy->profile_count; i++) {
#ifdef _WIN32
        if (_stricmp(policy->profiles[i].name, profile_id) == 0)
#else
        if (strcasecmp(policy->profiles[i].name, profile_id) == 0)
#endif
            return &policy->profiles[i];
    }
    return NULL;
}

const char *lab_policy_profile_for_time(const lab_policy_t *policy)
{
#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    int dow = st.wDayOfWeek;
    int now_min = st.wHour * 60 + st.wMinute;
#else
    time_t t = time(NULL);
    struct tm *lt = localtime(&t);
    int dow = lt->tm_wday;
    int now_min = lt->tm_hour * 60 + lt->tm_min;
#endif
    int i;

    if (!policy)
        return NULL;

    for (i = 0; i < policy->schedule_count; i++) {
        const lab_schedule_t *s = &policy->schedules[i];
        int start = s->hour_start * 60 + s->minute_start;
        int end = s->hour_end * 60 + s->minute_end;

        if (!(s->days_mask & (1 << dow)))
            continue;

        if (now_min >= start && now_min < end)
            return s->profile_id;
    }

    return policy->default_profile;
}
