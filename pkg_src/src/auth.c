/**
 * @file auth.c
 * @brief Authentication utilities for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "logger.h"
#include "utils.h"
#include "json/cJSON.h"

// Authentication data structure
typedef struct {
    char *username;
    char *password;
    char **publish_acl;
    int publish_acl_count;
    char **subscribe_acl;
    int subscribe_acl_count;
} auth_user_t;

// Global authentication state
static auth_user_t *users = NULL;
static int user_count = 0;
static int auth_initialized = 0;

// Free a user structure
static void free_user(auth_user_t *user) {
    int i;
    
    if (!user) {
        return;
    }
    
    free(user->username);
    free(user->password);
    
    for (i = 0; i < user->publish_acl_count; i++) {
        free(user->publish_acl[i]);
    }
    free(user->publish_acl);
    
    for (i = 0; i < user->subscribe_acl_count; i++) {
        free(user->subscribe_acl[i]);
    }
    free(user->subscribe_acl);
}

// Parse an ACL array from JSON
static int parse_acl(cJSON *acl_json, char ***acl, int *acl_count) {
    int i, count;
    
    if (!acl_json || !cJSON_IsArray(acl_json)) {
        *acl = NULL;
        *acl_count = 0;
        return 0;
    }
    
    count = cJSON_GetArraySize(acl_json);
    if (count <= 0) {
        *acl = NULL;
        *acl_count = 0;
        return 0;
    }
    
    *acl = (char **)malloc(sizeof(char *) * count);
    if (!*acl) {
        log_error("Failed to allocate memory for ACL");
        return -1;
    }
    
    for (i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(acl_json, i);
        if (!item || !cJSON_IsString(item)) {
            // Skip invalid items
            continue;
        }
        
        (*acl)[i] = utils_strdup(item->valuestring);
        if (!(*acl)[i]) {
            // Clean up on error
            int j;
            for (j = 0; j < i; j++) {
                free((*acl)[j]);
            }
            free(*acl);
            *acl = NULL;
            *acl_count = 0;
            return -1;
        }
    }
    
    *acl_count = count;
    return 0;
}

int auth_init(const char *auth_file) {
    FILE *fp;
    long file_size;
    char *file_content;
    cJSON *json, *users_json;
    int i, count;
    
    if (auth_initialized) {
        // Already initialized
        return 0;
    }
    
    if (!auth_file) {
        log_error("No authentication file specified");
        return -1;
    }
    
    // Open authentication file
    fp = fopen(auth_file, "r");
    if (!fp) {
        log_error("Failed to open authentication file: %s", auth_file);
        return -1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0) {
        fclose(fp);
        log_error("Empty authentication file: %s", auth_file);
        return -1;
    }
    
    // Allocate buffer for file content
    file_content = (char *)malloc(file_size + 1);
    if (!file_content) {
        fclose(fp);
        log_error("Failed to allocate memory for authentication file");
        return -1;
    }
    
    // Read file content
    if (fread(file_content, 1, file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(file_content);
        log_error("Failed to read authentication file");
        return -1;
    }
    
    file_content[file_size] = '\0';
    fclose(fp);
    
    // Parse JSON
    json = cJSON_Parse(file_content);
    free(file_content);
    
    if (!json) {
        log_error("Failed to parse authentication file as JSON");
        return -1;
    }
    
    // Get users array
    users_json = cJSON_GetObjectItem(json, "users");
    if (!users_json || !cJSON_IsArray(users_json)) {
        cJSON_Delete(json);
        log_error("Invalid users array in authentication file");
        return -1;
    }
    
    // Count users
    count = cJSON_GetArraySize(users_json);
    if (count <= 0) {
        cJSON_Delete(json);
        log_info("No users defined in authentication file");
        return 0;
    }
    
    // Allocate users array
    users = (auth_user_t *)calloc(count, sizeof(auth_user_t));
    if (!users) {
        cJSON_Delete(json);
        log_error("Failed to allocate memory for users");
        return -1;
    }
    
    // Parse users
    for (i = 0; i < count; i++) {
        cJSON *user_json = cJSON_GetArrayItem(users_json, i);
        cJSON *username_json, *password_json, *publish_acl_json, *subscribe_acl_json;
        
        if (!user_json || !cJSON_IsObject(user_json)) {
            // Skip invalid users
            continue;
        }
        
        // Parse username
        username_json = cJSON_GetObjectItem(user_json, "username");
        if (!username_json || !cJSON_IsString(username_json)) {
            // Skip users without username
            continue;
        }
        
        users[i].username = utils_strdup(username_json->valuestring);
        if (!users[i].username) {
            // Failed to allocate memory
            continue;
        }
        
        // Parse password
        password_json = cJSON_GetObjectItem(user_json, "password");
        if (!password_json || !cJSON_IsString(password_json)) {
            // Skip users without password
            free(users[i].username);
            users[i].username = NULL;
            continue;
        }
        
        users[i].password = utils_strdup(password_json->valuestring);
        if (!users[i].password) {
            // Failed to allocate memory
            free(users[i].username);
            users[i].username = NULL;
            continue;
        }
        
        // Parse publish ACL
        publish_acl_json = cJSON_GetObjectItem(user_json, "publish_acl");
        if (parse_acl(publish_acl_json, &users[i].publish_acl, &users[i].publish_acl_count) != 0) {
            // Failed to parse publish ACL
            free(users[i].username);
            free(users[i].password);
            users[i].username = NULL;
            users[i].password = NULL;
            continue;
        }
        
        // Parse subscribe ACL
        subscribe_acl_json = cJSON_GetObjectItem(user_json, "subscribe_acl");
        if (parse_acl(subscribe_acl_json, &users[i].subscribe_acl, &users[i].subscribe_acl_count) != 0) {
            // Failed to parse subscribe ACL
            free(users[i].username);
            free(users[i].password);
            free(users[i].publish_acl);
            users[i].username = NULL;
            users[i].password = NULL;
            users[i].publish_acl = NULL;
            users[i].publish_acl_count = 0;
            continue;
        }
        
        user_count++;
    }
    
    cJSON_Delete(json);
    auth_initialized = 1;
    
    log_info("Authentication initialized with %d users", user_count);
    return 0;
}

void auth_cleanup(void) {
    int i;
    
    if (!auth_initialized) {
        return;
    }
    
    for (i = 0; i < user_count; i++) {
        free_user(&users[i]);
    }
    
    free(users);
    users = NULL;
    user_count = 0;
    auth_initialized = 0;
}

int auth_authenticate(const char *username, const char *password) {
    int i;
    
    if (!auth_initialized) {
        // Authentication not initialized, allow everyone
        return 1;
    }
    
    if (!username || !password) {
        return 0;
    }
    
    for (i = 0; i < user_count; i++) {
        if (users[i].username && strcmp(users[i].username, username) == 0) {
            // Found user, check password
            return users[i].password && strcmp(users[i].password, password) == 0;
        }
    }
    
    return 0;
}

int auth_check_publish(const char *username, const char *topic) {
    int i, j;
    
    if (!auth_initialized) {
        // Authentication not initialized, allow everything
        return 1;
    }
    
    if (!username || !topic) {
        return 0;
    }
    
    for (i = 0; i < user_count; i++) {
        if (users[i].username && strcmp(users[i].username, username) == 0) {
            // Found user, check ACL
            for (j = 0; j < users[i].publish_acl_count; j++) {
                if (utils_topic_matches_subscription(topic, users[i].publish_acl[j])) {
                    return 1;
                }
            }
            
            // No matching ACL
            return 0;
        }
    }
    
    // User not found
    return 0;
}

int auth_check_subscribe(const char *username, const char *topic) {
    int i, j;
    
    if (!auth_initialized) {
        // Authentication not initialized, allow everything
        return 1;
    }
    
    if (!username || !topic) {
        return 0;
    }
    
    for (i = 0; i < user_count; i++) {
        if (users[i].username && strcmp(users[i].username, username) == 0) {
            // Found user, check ACL
            for (j = 0; j < users[i].subscribe_acl_count; j++) {
                if (utils_topic_matches_subscription(topic, users[i].subscribe_acl[j])) {
                    return 1;
                }
            }
            
            // No matching ACL
            return 0;
        }
    }
    
    // User not found
    return 0;
}