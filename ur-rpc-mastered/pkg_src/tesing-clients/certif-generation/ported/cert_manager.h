/*
 * Certificate Manager - Header File
 * Provides certificate generation, validation, and SSL connection management
 */

#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <mosquitto.h>
#include "cJSON.h"

// Certificate types
#define CERT_TYPE_GENERIC "generic"
#define CERT_TYPE_CLIENT_SPECIFIC "client_specific"

// MQTT topics for certificate operations
#define CERT_REQUEST_TOPIC "sys/cert/request"
#define CERT_RESPONSE_TOPIC "sys/cert/response"

// Configuration constants
#define MAX_PATH_LENGTH 512
#define MAX_CLIENT_ID_LENGTH 128
#define MAX_HOSTNAME_LENGTH 256
#define MAX_RESPONSE_WAIT_TIME 30
#define CERT_DIRECTORY "generated_certs"

// Certificate request/response status
typedef enum {
    CERT_STATUS_SUCCESS = 0,
    CERT_STATUS_ERROR = -1,
    CERT_STATUS_TIMEOUT = -2,
    CERT_STATUS_INVALID_RESPONSE = -3,
    CERT_STATUS_FILE_ERROR = -4,
    CERT_STATUS_ALREADY_EXISTS = 1
} cert_status_t;

// Certificate file information
typedef struct {
    char cert_path[MAX_PATH_LENGTH];
    char key_path[MAX_PATH_LENGTH];
    time_t creation_time;
    bool exists;
    bool valid;
} cert_file_info_t;

// Certificate request parameters
typedef struct {
    char client_id[MAX_CLIENT_ID_LENGTH];
    char cert_type[32];
    char common_name[MAX_HOSTNAME_LENGTH];
    char organization[128];
    char country[8];
    int validity_days;
    time_t timestamp;
} cert_request_params_t;

// Certificate response data
typedef struct {
    cert_status_t status;
    char error_message[256];
    char certificate_data[8192];
    char private_key_data[8192];
    char cert_filename[MAX_PATH_LENGTH];
    char key_filename[MAX_PATH_LENGTH];
} cert_response_data_t;

// Certificate manager context
typedef struct {
    struct mosquitto *mosq;
    char client_id[MAX_CLIENT_ID_LENGTH];
    char broker_host[MAX_HOSTNAME_LENGTH];
    int broker_port;
    bool use_ssl;
    char ca_cert_file[MAX_PATH_LENGTH];
    bool connected;
    bool response_received;
    cert_response_data_t last_response;
    void *user_data;
} cert_manager_t;

// Function declarations

// Certificate file management
cert_status_t cert_check_existing_files(const char *client_id, const char *cert_type, cert_file_info_t *file_info);
cert_status_t cert_create_directory_structure(void);
char* cert_generate_filename(const char *client_id, const char *cert_type, const char *extension);
cert_status_t cert_validate_file_permissions(const char *cert_path, const char *key_path);

// Certificate request/response handling
char* cert_create_request_json(const cert_request_params_t *params);
cert_status_t cert_parse_response_json(const char *json_data, cert_response_data_t *response);
cert_status_t cert_save_files(const cert_response_data_t *response);

// MQTT certificate operations
cert_status_t cert_manager_init(cert_manager_t *manager, const char *client_id, 
                               const char *broker_host, int broker_port, bool use_ssl);
cert_status_t cert_manager_connect(cert_manager_t *manager);
cert_status_t cert_manager_disconnect(cert_manager_t *manager);
cert_status_t cert_manager_cleanup(cert_manager_t *manager);

// Certificate generation requests
cert_status_t cert_request_generic(cert_manager_t *manager, const cert_request_params_t *params);
cert_status_t cert_request_client_specific(cert_manager_t *manager, const cert_request_params_t *params);
cert_status_t cert_request_certificate(cert_manager_t *manager, const cert_request_params_t *params);
cert_status_t cert_wait_for_response(cert_manager_t *manager, int timeout_seconds);

// SSL connection with certificate validation
cert_status_t cert_setup_ssl_connection(struct mosquitto *mosq, const char *cert_path, 
                                       const char *key_path, const char *ca_cert_path);
cert_status_t cert_connect_with_ssl(cert_manager_t *manager, const char *cert_path, const char *key_path);

// Utility functions
const char* cert_status_to_string(cert_status_t status);
void cert_print_file_info(const cert_file_info_t *file_info);
bool cert_is_file_readable(const char *filepath);
time_t cert_get_file_creation_time(const char *filepath);

// Callback function types
typedef void (*cert_response_callback_t)(cert_manager_t *manager, const cert_response_data_t *response);
typedef void (*cert_connection_callback_t)(cert_manager_t *manager, bool connected);

// Advanced features
cert_status_t cert_manager_set_response_callback(cert_manager_t *manager, cert_response_callback_t callback);
cert_status_t cert_manager_set_connection_callback(cert_manager_t *manager, cert_connection_callback_t callback);

// Certificate lifecycle management
cert_status_t cert_check_expiration(const char *cert_path, int *days_until_expiry);
cert_status_t cert_auto_renew_if_needed(cert_manager_t *manager, const cert_request_params_t *params, int renewal_threshold_days);

// Batch operations
typedef struct {
    cert_request_params_t *requests;
    int count;
    int completed;
    cert_status_t *results;
} cert_batch_request_t;

cert_status_t cert_batch_request_init(cert_batch_request_t *batch, int request_count);
cert_status_t cert_batch_add_request(cert_batch_request_t *batch, const cert_request_params_t *params);
cert_status_t cert_batch_execute(cert_manager_t *manager, cert_batch_request_t *batch);
void cert_batch_cleanup(cert_batch_request_t *batch);

#endif // CERT_MANAGER_H
