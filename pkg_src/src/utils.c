/**
 * @file utils.c
 * @brief Utility functions for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "utils.h"
#include "logger.h"

/**
 * Generate a random client ID
 */
char *utils_generate_client_id(char *buffer, size_t size) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static const size_t charset_size = sizeof(charset) - 1;
    size_t i;
    
    if (!buffer || size < 2) {
        return NULL;
    }
    
    // Seed the random number generator if needed
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    // Generate random ID
    for (i = 0; i < size - 1; i++) {
        buffer[i] = charset[rand() % charset_size];
    }
    
    buffer[size - 1] = '\0';
    return buffer;
}

/**
 * Check if a topic matches a subscription pattern
 */
int utils_topic_matches_subscription(const char *topic, const char *subscription) {
    const char *t = topic;
    const char *s = subscription;
    
    if (!topic || !subscription) {
        return 0;
    }
    
    // Simple case: exact match
    if (strcmp(topic, subscription) == 0) {
        return 1;
    }
    
    // Handle wildcards
    while (*t && *s) {
        if (*s == '+') {
            // Single-level wildcard
            // Skip to the next level in the topic
            s++;
            
            // Skip to the next level in the subscription
            while (*t && *t != '/') {
                t++;
            }
            
            // Both should be at '/' or end of string
            if (*t != *s) {
                if (!*t && *s == '/') {
                    return 0;
                } else if (!*s && *t == '/') {
                    return 0;
                }
            }
        } else if (*s == '#') {
            // Multi-level wildcard
            // Must be the last character in the subscription
            if (*(s + 1) == '\0') {
                return 1;
            } else if (*(s + 1) == '/' && *(s + 2) == '\0') {
                // Allow # at the end with a trailing /
                return 1;
            } else {
                // Invalid use of #
                return 0;
            }
        } else {
            // Regular character - must match exactly
            if (*t != *s) {
                return 0;
            }
            t++;
            s++;
        }
    }
    
    // Both strings must be at the end
    return (*t == '\0' && *s == '\0');
}

/**
 * Duplicate a string
 */
char *utils_strdup(const char *str) {
    char *copy;
    size_t len;
    
    if (!str) {
        return NULL;
    }
    
    len = strlen(str) + 1;
    copy = (char *)malloc(len);
    if (!copy) {
        log_error("Failed to allocate memory for string duplication");
        return NULL;
    }
    
    return (char *)memcpy(copy, str, len);
}

/**
 * Duplicate a memory block
 */
void *utils_memdup(const void *ptr, size_t size) {
    void *copy;
    
    if (!ptr || size == 0) {
        return NULL;
    }
    
    copy = malloc(size);
    if (!copy) {
        log_error("Failed to allocate memory for memory duplication");
        return NULL;
    }
    
    return memcpy(copy, ptr, size);
}

/**
 * Convert a string to lowercase
 */
char *utils_strlower(char *str) {
    char *p;
    
    if (!str) {
        return NULL;
    }
    
    for (p = str; *p; p++) {
        *p = tolower(*p);
    }
    
    return str;
}

/**
 * Convert a string to uppercase
 */
char *utils_strupper(char *str) {
    char *p;
    
    if (!str) {
        return NULL;
    }
    
    for (p = str; *p; p++) {
        *p = toupper(*p);
    }
    
    return str;
}

/**
 * Trim whitespace from the beginning and end of a string
 */
char *utils_strtrim(char *str) {
    char *start, *end;
    
    if (!str) {
        return NULL;
    }
    
    // Trim leading whitespace
    for (start = str; *start && isspace(*start); start++) {
        // Just iterate
    }
    
    // Empty string case
    if (*start == '\0') {
        *str = '\0';
        return str;
    }
    
    // Trim trailing whitespace
    end = start + strlen(start) - 1;
    while (end > start && isspace(*end)) {
        end--;
    }
    
    // Terminate the string
    *(end + 1) = '\0';
    
    // If there was leading whitespace, move the trimmed string to the beginning
    if (start != str) {
        memmove(str, start, (end - start + 2));
    }
    
    return str;
}

/**
 * Split a string into tokens
 */
int utils_strsplit(const char *str, char delim, char **tokens, int max_tokens) {
    const char *p, *q;
    int count = 0;
    
    if (!str || !tokens || max_tokens <= 0) {
        return 0;
    }
    
    p = str;
    
    // Skip leading delimiters
    while (*p && *p == delim) {
        p++;
    }
    
    while (*p && count < max_tokens) {
        q = p;
        
        // Find the end of the token
        while (*q && *q != delim) {
            q++;
        }
        
        // Allocate and copy token
        tokens[count] = (char *)malloc(q - p + 1);
        if (!tokens[count]) {
            // Failed to allocate memory, clean up
            int i;
            for (i = 0; i < count; i++) {
                free(tokens[i]);
                tokens[i] = NULL;
            }
            return 0;
        }
        
        memcpy(tokens[count], p, q - p);
        tokens[count][q - p] = '\0';
        count++;
        
        // Skip to the next token
        p = q;
        while (*p && *p == delim) {
            p++;
        }
    }
    
    return count;
}

/**
 * Join tokens into a string
 */
char *utils_strjoin(char **tokens, int token_count, char delim, char *result, size_t result_size) {
    int i;
    size_t pos = 0;
    
    if (!tokens || token_count <= 0 || !result || result_size <= 0) {
        return NULL;
    }
    
    result[0] = '\0';
    
    for (i = 0; i < token_count; i++) {
        size_t token_len;
        
        if (!tokens[i]) {
            continue;
        }
        
        token_len = strlen(tokens[i]);
        
        // Check if we have enough space
        if (pos + token_len + (i > 0 ? 1 : 0) >= result_size) {
            return NULL;
        }
        
        // Add delimiter if not first token
        if (i > 0) {
            result[pos++] = delim;
        }
        
        // Copy token
        memcpy(result + pos, tokens[i], token_len);
        pos += token_len;
        result[pos] = '\0';
    }
    
    return result;
}

/**
 * URL encode a string
 */
char *utils_url_encode(const char *str, char *result, size_t result_size) {
    const char *p;
    size_t pos = 0;
    
    if (!str || !result || result_size <= 0) {
        return NULL;
    }
    
    for (p = str; *p && pos + 1 < result_size; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            // Unreserved characters - copy as is
            result[pos++] = *p;
        } else {
            // Reserved characters - percent encode
            if (pos + 3 >= result_size) {
                // Not enough space
                result[pos] = '\0';
                return NULL;
            }
            
            sprintf(result + pos, "%%%02X", (unsigned char)*p);
            pos += 3;
        }
    }
    
    result[pos] = '\0';
    return result;
}

/**
 * URL decode a string
 */
char *utils_url_decode(const char *str, char *result, size_t result_size) {
    const char *p;
    size_t pos = 0;
    
    if (!str || !result || result_size <= 0) {
        return NULL;
    }
    
    for (p = str; *p && pos + 1 < result_size; p++) {
        if (*p == '%' && isxdigit(*(p + 1)) && isxdigit(*(p + 2))) {
            // Percent-encoded character
            char hex[3] = { *(p + 1), *(p + 2), '\0' };
            int value;
            sscanf(hex, "%x", &value);
            result[pos++] = (char)value;
            p += 2;
        } else if (*p == '+') {
            // Plus sign becomes space
            result[pos++] = ' ';
        } else {
            // Regular character
            result[pos++] = *p;
        }
    }
    
    result[pos] = '\0';
    return result;
}