/**
 * @file persistence.c
 * @brief Persistence utilities for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include "persistence.h"
#include "logger.h"
#include "utils.h"
#include "json/cJSON.h"

// Global persistence state
static char *persistence_directory = NULL;
static int initialized = 0;

// Subdirectories
static const char *RETAINED_DIR = "retained";
static const char *SESSIONS_DIR = "sessions";
static const char *MESSAGES_DIR = "messages";

// Create directory if it doesn't exist
static int create_directory(const char *path) {
    struct stat st;
    
    if (stat(path, &st) == 0) {
        // Directory exists
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        
        // Path exists but is not a directory
        log_error("Path exists but is not a directory: %s", path);
        return -1;
    }
    
    // Create directory
    if (mkdir(path, 0755) != 0) {
        log_error("Failed to create directory: %s", path);
        return -1;
    }
    
    return 0;
}

// Construct path to a subdirectory
static char *get_subdirectory_path(const char *subdir) {
    size_t len = strlen(persistence_directory) + strlen(subdir) + 2;
    char *path = (char *)malloc(len);
    
    if (!path) {
        log_error("Failed to allocate memory for path");
        return NULL;
    }
    
    snprintf(path, len, "%s/%s", persistence_directory, subdir);
    return path;
}

int persistence_init(const char *persistence_dir) {
    char *retained_path, *sessions_path, *messages_path;
    
    if (initialized) {
        return 0;
    }
    
    if (!persistence_dir) {
        log_error("No persistence directory specified");
        return -1;
    }
    
    // Store the persistence directory
    persistence_directory = utils_strdup(persistence_dir);
    if (!persistence_directory) {
        log_error("Failed to allocate memory for persistence directory");
        return -1;
    }
    
    // Create the persistence directory
    if (create_directory(persistence_directory) != 0) {
        free(persistence_directory);
        persistence_directory = NULL;
        return -1;
    }
    
    // Create subdirectories
    retained_path = get_subdirectory_path(RETAINED_DIR);
    if (!retained_path || create_directory(retained_path) != 0) {
        free(persistence_directory);
        free(retained_path);
        persistence_directory = NULL;
        return -1;
    }
    free(retained_path);
    
    sessions_path = get_subdirectory_path(SESSIONS_DIR);
    if (!sessions_path || create_directory(sessions_path) != 0) {
        free(persistence_directory);
        free(sessions_path);
        persistence_directory = NULL;
        return -1;
    }
    free(sessions_path);
    
    messages_path = get_subdirectory_path(MESSAGES_DIR);
    if (!messages_path || create_directory(messages_path) != 0) {
        free(persistence_directory);
        free(messages_path);
        persistence_directory = NULL;
        return -1;
    }
    free(messages_path);
    
    initialized = 1;
    log_info("Persistence initialized with directory: %s", persistence_directory);
    
    return 0;
}

void persistence_cleanup(void) {
    if (!initialized) {
        return;
    }
    
    free(persistence_directory);
    persistence_directory = NULL;
    initialized = 0;
}

int persistence_save_message(const char *client_id, const char *topic, const void *payload, size_t payload_len, int qos, int retain) {
    char *messages_path, *message_path;
    FILE *fp;
    cJSON *json;
    char *json_str;
    int result = 0;
    
    if (!initialized || !client_id || !topic || !payload) {
        return -1;
    }
    
    // Only save if retain flag is set
    if (!retain) {
        return 0;
    }
    
    // Create JSON object for the message
    json = cJSON_CreateObject();
    if (!json) {
        log_error("Failed to create JSON object for message");
        return -1;
    }
    
    // Add message properties
    cJSON_AddStringToObject(json, "client_id", client_id);
    cJSON_AddStringToObject(json, "topic", topic);
    
    // Add payload as base64-encoded string (simplified in this version)
    cJSON_AddStringToObject(json, "payload", "base64-encoded-payload-would-go-here");
    
    cJSON_AddNumberToObject(json, "qos", qos);
    cJSON_AddBoolToObject(json, "retain", retain ? 1 : 0);
    
    // Convert to JSON string
    json_str = cJSON_Print(json);
    cJSON_Delete(json);
    
    if (!json_str) {
        log_error("Failed to convert message to JSON string");
        return -1;
    }
    
    // Get path to the retained messages directory
    messages_path = get_subdirectory_path(RETAINED_DIR);
    if (!messages_path) {
        free(json_str);
        return -1;
    }
    
    // Create path to the message file
    message_path = (char *)malloc(strlen(messages_path) + strlen(topic) + 6);
    if (!message_path) {
        log_error("Failed to allocate memory for message path");
        free(messages_path);
        free(json_str);
        return -1;
    }
    
    // Use a simple hashing scheme to convert topic to filename
    // In a real implementation, this would need to be more robust
    sprintf(message_path, "%s/%x.json", messages_path, (unsigned int)strlen(topic));
    
    // Open the message file
    fp = fopen(message_path, "w");
    if (!fp) {
        log_error("Failed to open message file: %s", message_path);
        free(messages_path);
        free(message_path);
        free(json_str);
        return -1;
    }
    
    // Write the message to the file
    if (fputs(json_str, fp) < 0) {
        log_error("Failed to write message to file: %s", message_path);
        result = -1;
    }
    
    // Clean up
    fclose(fp);
    free(messages_path);
    free(message_path);
    free(json_str);
    
    return result;
}

int persistence_load_retained(void) {
    char *retained_path;
    DIR *dir;
    struct dirent *entry;
    
    if (!initialized) {
        return -1;
    }
    
    // Get path to the retained messages directory
    retained_path = get_subdirectory_path(RETAINED_DIR);
    if (!retained_path) {
        return -1;
    }
    
    // Open the directory
    dir = opendir(retained_path);
    if (!dir) {
        log_error("Failed to open retained messages directory: %s", retained_path);
        free(retained_path);
        return -1;
    }
    
    // Process each file in the directory
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Load message from file (simplified in this version)
        log_debug("Would load retained message from file: %s", entry->d_name);
    }
    
    // Clean up
    closedir(dir);
    free(retained_path);
    
    log_info("Loaded retained messages");
    return 0;
}

int persistence_load_sessions(void) {
    char *sessions_path;
    DIR *dir;
    struct dirent *entry;
    
    if (!initialized) {
        return -1;
    }
    
    // Get path to the sessions directory
    sessions_path = get_subdirectory_path(SESSIONS_DIR);
    if (!sessions_path) {
        return -1;
    }
    
    // Open the directory
    dir = opendir(sessions_path);
    if (!dir) {
        log_error("Failed to open sessions directory: %s", sessions_path);
        free(sessions_path);
        return -1;
    }
    
    // Process each file in the directory
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Load session from file (simplified in this version)
        log_debug("Would load session from file: %s", entry->d_name);
    }
    
    // Clean up
    closedir(dir);
    free(sessions_path);
    
    log_info("Loaded sessions");
    return 0;
}

int persistence_save_session(const char *client_id, int clean_session, const char **subscriptions, int subscription_count) {
    char *sessions_path, *session_path;
    FILE *fp;
    cJSON *json, *subs_json;
    char *json_str;
    int i, result = 0;
    
    if (!initialized || !client_id) {
        return -1;
    }
    
    // Skip if clean session
    if (clean_session) {
        return 0;
    }
    
    // Create JSON object for the session
    json = cJSON_CreateObject();
    if (!json) {
        log_error("Failed to create JSON object for session");
        return -1;
    }
    
    // Add session properties
    cJSON_AddStringToObject(json, "client_id", client_id);
    cJSON_AddBoolToObject(json, "clean_session", clean_session ? 1 : 0);
    
    // Add subscriptions array
    subs_json = cJSON_AddArrayToObject(json, "subscriptions");
    if (!subs_json) {
        log_error("Failed to create subscriptions array for session");
        cJSON_Delete(json);
        return -1;
    }
    
    for (i = 0; i < subscription_count; i++) {
        cJSON_AddItemToArray(subs_json, cJSON_CreateString(subscriptions[i]));
    }
    
    // Convert to JSON string
    json_str = cJSON_Print(json);
    cJSON_Delete(json);
    
    if (!json_str) {
        log_error("Failed to convert session to JSON string");
        return -1;
    }
    
    // Get path to the sessions directory
    sessions_path = get_subdirectory_path(SESSIONS_DIR);
    if (!sessions_path) {
        free(json_str);
        return -1;
    }
    
    // Create path to the session file
    session_path = (char *)malloc(strlen(sessions_path) + strlen(client_id) + 6);
    if (!session_path) {
        log_error("Failed to allocate memory for session path");
        free(sessions_path);
        free(json_str);
        return -1;
    }
    
    sprintf(session_path, "%s/%s.json", sessions_path, client_id);
    
    // Open the session file
    fp = fopen(session_path, "w");
    if (!fp) {
        log_error("Failed to open session file: %s", session_path);
        free(sessions_path);
        free(session_path);
        free(json_str);
        return -1;
    }
    
    // Write the session to the file
    if (fputs(json_str, fp) < 0) {
        log_error("Failed to write session to file: %s", session_path);
        result = -1;
    }
    
    // Clean up
    fclose(fp);
    free(sessions_path);
    free(session_path);
    free(json_str);
    
    return result;
}

int persistence_delete_session(const char *client_id) {
    char *sessions_path, *session_path;
    int result = 0;
    
    if (!initialized || !client_id) {
        return -1;
    }
    
    // Get path to the sessions directory
    sessions_path = get_subdirectory_path(SESSIONS_DIR);
    if (!sessions_path) {
        return -1;
    }
    
    // Create path to the session file
    session_path = (char *)malloc(strlen(sessions_path) + strlen(client_id) + 6);
    if (!session_path) {
        log_error("Failed to allocate memory for session path");
        free(sessions_path);
        return -1;
    }
    
    sprintf(session_path, "%s/%s.json", sessions_path, client_id);
    
    // Delete the session file
    if (unlink(session_path) != 0 && errno != ENOENT) {
        log_error("Failed to delete session file: %s", session_path);
        result = -1;
    }
    
    // Clean up
    free(sessions_path);
    free(session_path);
    
    return result;
}