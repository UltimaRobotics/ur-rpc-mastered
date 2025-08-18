#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Forward declare to avoid circular dependencies
#ifndef MAX_CLIENT_ID_LEN
#define MAX_CLIENT_ID_LEN 64
#endif

#define MAX_CERT_SIZE 4096
#define MAX_KEY_SIZE 2048
#define MAX_FILENAME_LEN 256
#define MAX_ERROR_MSG_LEN 512
#define MAX_JSON_RESPONSE_LEN 2048
#define MAX_ENVIRONMENT_LEN 16
#define MAX_HEX_SUFFIX_LEN 12
#define MAX_METADATA_LEN 512

// Certificate request status codes
typedef enum {
    CERT_REQUEST_SUCCESS = 0,
    CERT_REQUEST_FAILED = 1,
    CERT_REQUEST_TIMEOUT = 2,
    CERT_REQUEST_INVALID_RESPONSE = 3,
    CERT_REQUEST_BROKER_NOT_SSL = 4,
    CERT_REQUEST_CONNECTION_FAILED = 5,
    CERT_REQUEST_PARSE_ERROR = 6
} cert_request_status_t;

// Certificate generation request types
typedef enum {
    CERT_TYPE_CLIENT = 0,
    CERT_TYPE_SERVER = 1,
    CERT_TYPE_CA = 2
} cert_type_t;

// Enhanced certificate types for broker compatibility
typedef enum {
    CERT_TYPE_GENERIC = 0,    // Generic certificate - can be used by multiple clients
    CERT_TYPE_CLIENT_SPECIFIC = 1  // Client-specific certificate - embedded with client ID
} cert_type_e;

// Environment-based certificate categories
typedef enum {
    CERT_ENV_API = 0,      // API environment certificates
    CERT_ENV_DEV = 1,      // Development environment certificates  
    CERT_ENV_PROD = 2,     // Production environment certificates
    CERT_ENV_STAGING = 3   // Staging environment certificates
} cert_environment_t;

// Certificate validation status
typedef enum {
    CERT_VALID = 0,
    CERT_INVALID_FORMAT = 1,
    CERT_EXPIRED = 2,
    CERT_NOT_YET_VALID = 3,
    CERT_SIGNATURE_INVALID = 4,
    CERT_FILE_NOT_FOUND = 5
} cert_validation_status_t;

// Certificate metadata structure for enhanced tracking
typedef struct {
    char environment[MAX_ENVIRONMENT_LEN];   // Environment: api, dev, prod, staging
    char hex_suffix[MAX_HEX_SUFFIX_LEN];     // 8-character hex suffix for uniqueness
    cert_environment_t env_type;             // Environment type enum
    time_t created_at;                       // Creation timestamp
    time_t last_used;                        // Last usage timestamp
    int usage_count;                         // Number of times certificate was used
    char metadata[MAX_METADATA_LEN];         // Additional metadata (JSON format)
    int version;                             // Certificate version for rollback
} cert_metadata_t;

// Enhanced certificate request message structure
typedef struct {
    char client_id[MAX_CLIENT_ID_LEN];
    char cert_filename[MAX_FILENAME_LEN];
    char key_filename[MAX_FILENAME_LEN];
    char common_name[256];
    char organization[256];
    char country[4];
    uint32_t validity_days;
    uint32_t key_size;
    char reference_field[128];               // Custom reference field for client to identify the certificate
    cert_type_e cert_type;                   // Certificate type (generic or client-specific)
    char authorized_clients[512];            // Comma-separated list of client IDs authorized to use generic certificates
    cert_type_t cert_request_type;           // Enhanced certificate type
    bool enable_client_auth;                 // Enable client authentication
    cert_environment_t environment;          // Environment type (api, dev, prod, staging)
    bool auto_generate_suffix;               // Auto-generate hex suffix if true
    char custom_hex_suffix[MAX_HEX_SUFFIX_LEN]; // Custom hex suffix (optional)
    cert_metadata_t metadata;                // Certificate metadata
} cert_request_t;

// Enhanced certificate response message structure
typedef struct {
    cert_request_status_t status;
    char error_message[MAX_ERROR_MSG_LEN];
    char certificate_pem[MAX_CERT_SIZE];
    char private_key_pem[MAX_KEY_SIZE];
    char ca_certificate_pem[MAX_CERT_SIZE];
    char cert_filename[MAX_FILENAME_LEN];
    char key_filename[MAX_FILENAME_LEN];
    time_t issued_at;
    time_t expires_at;
    bool broker_ssl_enabled;
    
    // Legacy fields for compatibility
    char client_id[MAX_CLIENT_ID_LEN];
    bool success;
    char cert_path[512];
    char key_path[512];
    char reference_field[128];  // Echo back the reference field
    char cert_serial[32];       // Unique certificate serial number
    char expiry_date[32];       // Certificate expiration date
} cert_response_t;

// Certificate info structure for validation/inspection
typedef struct {
    char subject[512];
    char issuer[512];
    char serial_number[64];
    time_t not_before;
    time_t not_after;
    char fingerprint[128];
    int key_size;
    char algorithm[64];
    bool is_ca;
    bool is_self_signed;
} cert_info_t;

// Enhanced certificate registry entry for tracking generated certificates
typedef struct cert_registry_entry {
    char client_id[MAX_CLIENT_ID_LEN];
    char reference_field[128];
    char cert_filename[MAX_FILENAME_LEN];
    char key_filename[MAX_FILENAME_LEN];
    char cert_serial[32];
    char cert_path[512];
    char key_path[512];
    time_t creation_time;
    time_t expiry_time;
    bool active;
    cert_type_e cert_type;           // Certificate type
    char authorized_clients[512];    // For generic certificates - authorized client list
    uint32_t usage_count;           // Number of times certificate has been used
    cert_environment_t environment;  // Environment type
    char hex_suffix[MAX_HEX_SUFFIX_LEN]; // Unique hex suffix
    cert_metadata_t metadata;        // Extended metadata
    int version;                     // Certificate version for rollback
    struct cert_registry_entry* next;
} cert_registry_entry_t;

// Certificate manager initialization and cleanup
bool cert_manager_init(const char* ca_cert_path, const char* ca_key_path, const char* output_dir);
void cert_manager_cleanup(void);

// Main certificate generation function
bool cert_manager_generate_certificate(const cert_request_t* request, cert_response_t* response);

// Certificate request parsing from MQTT message
bool cert_manager_parse_request(const char* json_payload, cert_request_t* request);

// Certificate response serialization to MQTT message
char* cert_manager_serialize_response(const cert_response_t* response);

// Validation functions
bool cert_manager_validate_request(const cert_request_t* request);
bool cert_manager_validate_filename(const char* filename);

// Certificate file operations
bool cert_manager_save_certificate(const char* cert_pem, const char* filepath);
bool cert_manager_save_private_key(const char* key_pem, const char* filepath);

// Internal certificate generation functions
bool cert_manager_generate_keypair(char** private_key_pem, char** public_key_pem, int key_size);
bool cert_manager_create_certificate(const char* public_key_pem, const cert_request_t* request, char** cert_pem);
bool cert_manager_sign_certificate(const char* cert_csr, const char* ca_cert, const char* ca_key, char** signed_cert);

// Certificate registry management
bool cert_manager_register_certificate(const cert_request_t* request, const cert_response_t* response);
cert_registry_entry_t* cert_manager_find_certificate_by_client_and_reference(const char* client_id, const char* reference_field);
cert_registry_entry_t* cert_manager_list_client_certificates(const char* client_id);
bool cert_manager_revoke_certificate(const char* client_id, const char* reference_field);
void cert_manager_cleanup_expired_certificates(void);

// Certificate information and listing
int cert_manager_get_client_certificate_count(const char* client_id);
char* cert_manager_serialize_certificate_list(const char* client_id);

// Enhanced certificate management for generic and client-specific certificates
bool cert_manager_validate_client_authorization(const char* client_id, const cert_registry_entry_t* cert_entry);
bool cert_manager_create_certificate_directory(const char* client_id, const char* cert_type_name);
char* cert_manager_get_certificate_storage_path(const char* client_id, const char* reference_field, cert_type_e cert_type);
bool cert_manager_save_certificate_for_reuse(const cert_request_t* request, const cert_response_t* response);
cert_registry_entry_t* cert_manager_find_reusable_certificate(const char* client_id, const char* reference_field);
char* cert_manager_serialize_generic_certificate_list(void);
bool cert_manager_verify_client_specific_certificate(const char* client_id, const char* cert_path);

// ===== NEW ENHANCED ENVIRONMENT-BASED API FUNCTIONS =====

/**
 * Request certificate generation with environment-based naming
 * @param request Enhanced certificate request with environment parameters
 * @param response Response structure to fill
 * @return true on success, false on failure
 */
bool cert_manager_request_environment_certificate(const cert_request_t* request, cert_response_t* response);

/**
 * List certificates by environment
 * @param environment Environment type (api, dev, prod, staging)
 * @param response JSON response with certificate list
 * @param response_size Size of response buffer
 * @return true on success, false on failure
 */
bool cert_manager_list_certificates_by_environment(cert_environment_t environment, char* response, size_t response_size);

/**
 * Batch generate certificates for multiple clients
 * @param requests Array of certificate requests
 * @param request_count Number of requests
 * @param responses Array of response structures
 * @return true on success, false on failure
 */
bool cert_manager_batch_generate_certificates(const cert_request_t* requests, int request_count, cert_response_t* responses);

/**
 * Monitor certificate expiration
 * @param environment Environment to check (or -1 for all)
 * @param days_until_expiry Check certificates expiring within N days
 * @param response JSON response with expiring certificates
 * @param response_size Size of response buffer
 * @return true on success, false on failure
 */
bool cert_manager_monitor_certificate_expiration(cert_environment_t environment, int days_until_expiry, char* response, size_t response_size);

/**
 * Revoke certificate by environment and client
 * @param environment Environment type
 * @param client_id Client ID of the certificate to revoke
 * @param response Response structure to fill
 * @return true on success, false on failure
 */
bool cert_manager_revoke_certificate_by_environment(cert_environment_t environment, const char* client_id, cert_response_t* response);

/**
 * Search certificates by metadata
 * @param search_query JSON query for certificate search
 * @param response JSON response with matching certificates
 * @param response_size Size of response buffer
 * @return true on success, false on failure
 */
bool cert_manager_search_certificates(const char* search_query, char* response, size_t response_size);

/**
 * Rollback certificate to previous version
 * @param environment Environment type
 * @param client_id Client ID
 * @param version Version to rollback to
 * @param response Response structure to fill
 * @return true on success, false on failure
 */
bool cert_manager_rollback_certificate(cert_environment_t environment, const char* client_id, int version, cert_response_t* response);

/**
 * Generate certificate filename with environment and hex suffix
 * @param environment Environment type
 * @param client_id Client ID
 * @param reference_field Reference field
 * @param hex_suffix Hex suffix (auto-generated if NULL)
 * @param cert_filename Buffer for certificate filename
 * @param key_filename Buffer for key filename
 * @return true on success, false on failure
 */
bool cert_manager_generate_environment_filename(cert_environment_t environment, const char* client_id, const char* reference_field, 
                                               const char* hex_suffix, char* cert_filename, char* key_filename);

/**
 * Get environment string from enum
 * @param environment Environment enum value
 * @return String representation of environment
 */
const char* cert_manager_get_environment_string(cert_environment_t environment);

/**
 * Parse environment string to enum
 * @param env_string Environment string (api, dev, prod, staging)
 * @return cert_environment_t enum value
 */
cert_environment_t cert_manager_parse_environment_string(const char* env_string);

/**
 * Generate random hex suffix
 * @param suffix Buffer for hex suffix (minimum 9 characters)
 * @return true on success, false on failure
 */
bool cert_manager_generate_hex_suffix(char* suffix);

/**
 * Track certificate usage
 * @param environment Environment type
 * @param client_id Client ID
 * @return true on success, false on failure
 */
bool cert_manager_track_certificate_usage(cert_environment_t environment, const char* client_id);

/**
 * Validate a certificate file
 * @param cert_file Path to certificate file
 * @param cert_info Structure to fill with certificate information
 * @return cert_validation_status_t indicating validation result
 */
cert_validation_status_t cert_manager_validate_certificate(const char* cert_file, cert_info_t* cert_info);

/**
 * Get human-readable error message for status code
 * @param status Status code
 * @return String description of the status
 */
const char* cert_manager_get_status_string(cert_request_status_t status);

/**
 * Get human-readable validation message for validation status
 * @param status Validation status code
 * @return String description of the validation status
 */
const char* cert_manager_get_validation_string(cert_validation_status_t status);

#endif // CERT_MANAGER_H