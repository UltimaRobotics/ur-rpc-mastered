#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

// Legacy compatibility wrapper functions for ur-logger-api
int log_init(const char *log_file, int log_level, int log_to_console) {
    // Convert old log levels to ur-logger-api levels
    log_level_t ur_level;
    switch(log_level) {
        case 0: ur_level = LOG_ERROR; break;
        case 1: ur_level = LOG_WARN; break;
        case 2: ur_level = LOG_INFO; break;
        case 3: ur_level = LOG_DEBUG; break;
        default: ur_level = LOG_INFO; break;
    }
    
    // Set up logger flags
    log_flags_t flags = LOG_FLAG_TIMESTAMP;
    if (log_to_console) {
        flags |= LOG_FLAG_CONSOLE | LOG_FLAG_COLOR;
    }
    if (log_file && strlen(log_file) > 0) {
        flags |= LOG_FLAG_FILE;
    }
    
    return logger_init(ur_level, flags, log_file);
}

void log_cleanup(void) {
    logger_destroy();
}

char* get_timestamp(char *buffer, size_t buffer_size) {
    struct timeval tv;
    struct tm *tm_info;
    
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    
    snprintf(buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             tv.tv_usec / 1000);
    
    return buffer;
}

long get_memory_usage(void) {
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) return -1;
    
    char line[256];
    long memory_kb = -1;
    
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld kB", &memory_kb);
            break;
        }
    }
    
    fclose(file);
    return memory_kb > 0 ? memory_kb * 1024 : -1;
}

long get_system_uptime(void) {
    FILE *file = fopen("/proc/uptime", "r");
    if (!file) return -1;
    
    double uptime;
    if (fscanf(file, "%lf", &uptime) == 1) {
        fclose(file);
        return (long)uptime;
    }
    
    fclose(file);
    return -1;
}

char* format_bytes(uint64_t bytes, char *buffer, size_t buffer_size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = (double)bytes;
    
    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }
    
    if (unit_index == 0) {
        snprintf(buffer, buffer_size, "%lu %s", bytes, units[unit_index]);
    } else {
        snprintf(buffer, buffer_size, "%.2f %s", size, units[unit_index]);
    }
    
    return buffer;
}

size_t safe_strncpy(char *dst, const char *src, size_t dst_size) {
    if (!dst || !src || dst_size == 0) return 0;
    
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    
    return copy_len;
}

size_t safe_strncat(char *dst, const char *src, size_t dst_size) {
    if (!dst || !src || dst_size == 0) return 0;
    
    size_t dst_len = strlen(dst);
    if (dst_len >= dst_size - 1) return dst_len;
    
    size_t remaining = dst_size - dst_len - 1;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < remaining) ? src_len : remaining;
    
    memcpy(dst + dst_len, src, copy_len);
    dst[dst_len + copy_len] = '\0';
    
    return dst_len + copy_len;
}

void hex_dump(const void *data, size_t length, const char *prefix) {
    const uint8_t *bytes = (const uint8_t*)data;
    
    for (size_t i = 0; i < length; i += 16) {
        printf("%s%04zx: ", prefix ? prefix : "", i);
        
        // Print hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", bytes[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }
        
        printf(" |");
        
        // Print ASCII characters
        for (size_t j = 0; j < 16 && i + j < length; j++) {
            uint8_t c = bytes[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("|\n");
    }
}

uint32_t string_hash(const char *str) {
    if (!str) return 0;
    
    uint32_t hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

int is_numeric(const char *str) {
    if (!str || *str == '\0') return 0;
    
    if (*str == '-' || *str == '+') str++;
    
    int has_digits = 0;
    while (*str) {
        if (!isdigit(*str)) return 0;
        has_digits = 1;
        str++;
    }
    
    return has_digits;
}

char* trim_whitespace(char *str) {
    if (!str) return NULL;
    
    // Trim leading whitespace
    while (isspace(*str)) str++;
    
    if (*str == '\0') return str;
    
    // Trim trailing whitespace
    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    
    *(end + 1) = '\0';
    return str;
}

int parse_boolean(const char *str) {
    if (!str) return -1;
    
    char *trimmed = trim_whitespace((char*)str);
    
    if (strcasecmp(trimmed, "true") == 0 || 
        strcasecmp(trimmed, "yes") == 0 || 
        strcmp(trimmed, "1") == 0) {
        return 1;
    }
    
    if (strcasecmp(trimmed, "false") == 0 || 
        strcasecmp(trimmed, "no") == 0 || 
        strcmp(trimmed, "0") == 0) {
        return 0;
    }
    
    return -1;
}

int get_random_bytes(uint8_t *buffer, size_t length) {
    if (!buffer || length == 0) return -1;
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    
    ssize_t bytes_read = read(fd, buffer, length);
    close(fd);
    
    return (bytes_read == (ssize_t)length) ? 0 : -1;
}

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t crc32(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        crc = crc32_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

void sleep_ms(uint32_t milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

uint64_t get_monotonic_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int file_exists(const char *filepath) {
    if (!filepath) return 0;
    return access(filepath, F_OK) == 0 ? 1 : 0;
}

int create_directory(const char *path) {
    if (!path) return -1;
    
    char *path_copy = strdup(path);
    if (!path_copy) return -1;
    
    char *p = path_copy;
    
    // Skip leading slash
    if (*p == '/') p++;
    
    while (*p) {
        while (*p && *p != '/') p++;
        
        char temp = *p;
        *p = '\0';
        
        if (mkdir(path_copy, 0755) != 0 && errno != EEXIST) {
            free(path_copy);
            return -1;
        }
        
        *p = temp;
        if (*p) p++;
    }
    
    free(path_copy);
    return 0;
}

long get_file_size(const char *filepath) {
    if (!filepath) return -1;
    
    struct stat st;
    if (stat(filepath, &st) == 0) {
        return st.st_size;
    }
    
    return -1;
}

bool mqtt_topic_matches_filter(const char *filter, const char *topic) {
    if (!filter || !topic) return false;
    
    const char *f = filter;
    const char *t = topic;
    
    while (*f && *t) {
        if (*f == '#') {
            // Multi-level wildcard - matches everything from here on
            return true;
        } else if (*f == '+') {
            // Single-level wildcard - skip to next '/' in topic
            while (*t && *t != '/') t++;
            f++;
            // Skip past '/' in both filter and topic if present
            if (*f == '/' && *t == '/') {
                f++;
                t++;
            }
        } else if (*f == *t) {
            // Exact character match
            f++;
            t++;
        } else {
            // No match
            return false;
        }
    }
    
    // Check if we've consumed both strings completely
    // or if filter ends with # (multi-level wildcard)
    return (*f == '\0' && *t == '\0') || (*f == '#' && *(f+1) == '\0');
}
