#include "util.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define LAB_PATH_SEP '\\'
#include <direct.h>
#include <windows.h>
#define mkdir(path, mode) _mkdir(path)
#else
#define LAB_PATH_SEP '/'
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#endif

static char g_data_dir[512];
static char g_baseline_dir[512];
static char g_log_path[512];
static char g_policy_path[512];
static int  g_paths_init = 0;

static void init_paths(void)
{
    if (g_paths_init)
        return;

#ifdef _WIN32
    const char *base = "C:\\ProgramData\\LabAgent";
#else
    const char *base = "/var/lib/labagent";
#endif

    snprintf(g_data_dir, sizeof(g_data_dir), "%s%cdata", base, LAB_PATH_SEP);
    snprintf(g_baseline_dir, sizeof(g_baseline_dir), "%s%cbaseline", base, LAB_PATH_SEP);
    snprintf(g_log_path, sizeof(g_log_path), "%s%caudit.log", base, LAB_PATH_SEP);
    snprintf(g_policy_path, sizeof(g_policy_path), "%s%cpolicy.sealed", base, LAB_PATH_SEP);
    g_paths_init = 1;
}

const char *lab_data_dir(void)   { init_paths(); return g_data_dir; }
const char *lab_baseline_dir(void){ init_paths(); return g_baseline_dir; }
const char *lab_log_path(void)   { init_paths(); return g_log_path; }
const char *lab_policy_path(void){ init_paths(); return g_policy_path; }

uint64_t lab_now_unix(void)
{
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uli.QuadPart / 10000000ULL) - 11644473600ULL;
#else
    return (uint64_t)time(NULL);
#endif
}


#ifdef _WIN32

    uint64_t lab_monotonic_sec(void)
    {
        return (double)GetTickCount64() / 1000.0;
    }

#else 
    
    uint64_t lab_monotonic_sec(void)
    {
        struct timespec ts;
        if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0.0;
        return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
    }

#endif

void lab_sleep_ms(unsigned ms)
{
    #ifdef _WIN32
        Sleep(ms);
    #else
        usleep(ms * 1000);
    #endif
}


int lab_mkdir_p(const char *path)
{
    if(!path || !*path) return -1;
    char tmp[512];
    
    //check if the buffer is large enough
    if(strlen(path) >= sizeof(tmp)){
        return -1;
    }
    
    strcpy(tmp, path);

    for(char *p = tmp + 1; *p; ++p){
        #ifdef _WIN32
            if(*p == '\\' || *p == '/')
        #else 
            if(*p == '/')
        #endif
            {
                char saved = *p;
                *p = '\0';
                if(mkdir(tmp, 0755) != 0){
                    #ifdef _WIN32
                        if(getLastError() != ERROR_ALREADY_EXISTS)
                            return -1;
                    #else 
                        if(errno != EEXIST)
                            return -1;
                    #endif
                }
                *p = saved;
            }
        }
        if(mkdir(tmp, 0755) != 0)
        {
            #ifdef _WIN32
                if(getLastError() != ERROR_ALREADY_EXISTS)
                    return -1;
            #else 
                if(errno != EEXIST)
                    return -1;
            #endif
        }
    return 0;
}



int lab_get_hostname(char *buf, size_t len)
{
#ifdef _WIN32
    DWORD n = (DWORD)len;
    return GetComputerNameA(buf, &n) ? 0 : -1;
#else
    return gethostname(buf, len) == 0 ? 0 : -1;
#endif
}

int lab_get_agent_id(char *buf, size_t len)
{
    if (lab_get_hostname(buf, len) != 0)
        snprintf(buf, len, "lab-agent-unknown");
    return 0;
}
