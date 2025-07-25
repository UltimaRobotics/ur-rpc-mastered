#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdarg.h>
#include <time.h>

// Log levels
#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARN  1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_DEBUG 3

// Global log level
extern int g_log_level;
extern int g_log_to_console;

/**
 * Initialize logging system
 * @param log_file Path to log file (NULL for console only)
 * @param log_level Log level (0-3)
 * @param log_to_console Whether to log to console
 * @return 0 on success, -1 on error
 */
int log_init(const char *log_file, int log_level, int log_to_console);

/**
 * Cleanup logging system
 */
void log_cleanup(void);

/**
 * Log message
 * @param level Log level
 * @param file Source file name
 * @param line Line number
 * @param func Function name
 * @param format Format string
 * @param ... Format arguments
 */
void log_message(int level, const char *file, int line, const char *func, const char *format, ...);

// Logging macros
#define LOG_ERROR(format, ...) log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) log_message(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

/**
 * Get current timestamp as string
 * @param buffer Buffer to store timestamp
 * @param buffer_size Buffer size
 * @return Pointer to buffer
 */
char* get_timestamp(char *buffer, size_t buffer_size);

/**
 * Get memory usage in bytes
 * @return Memory usage in bytes, -1 on error
 */
long get_memory_usage(void);

/**
 * Get system uptime in seconds
 * @return Uptime in seconds, -1 on error
 */
long get_system_uptime(void);

/**
 * Convert bytes to human readable format
 * @param bytes Number of bytes
 * @param buffer Buffer to store result
 * @param buffer_size Buffer size
 * @return Pointer to buffer
 */
char* format_bytes(uint64_t bytes, char *buffer, size_t buffer_size);

/**
 * Safe string copy with null termination
 * @param dst Destination buffer
 * @param src Source string
 * @param dst_size Destination buffer size
 * @return Number of characters copied
 */
size_t safe_strncpy(char *dst, const char *src, size_t dst_size);

/**
 * Safe string concatenation with null termination
 * @param dst Destination buffer
 * @param src Source string
 * @param dst_size Destination buffer size
 * @return Number of characters in resulting string
 */
size_t safe_strncat(char *dst, const char *src, size_t dst_size);

/**
 * Hex dump for debugging
 * @param data Data buffer
 * @param length Data length
 * @param prefix Prefix for each line
 */
void hex_dump(const void *data, size_t length, const char *prefix);

/**
 * Calculate hash for string (simple hash function)
 * @param str Input string
 * @return Hash value
 */
uint32_t string_hash(const char *str);

/**
 * Check if string is numeric
 * @param str Input string
 * @return 1 if numeric, 0 otherwise
 */
int is_numeric(const char *str);

/**
 * Trim whitespace from string
 * @param str Input string (modified in place)
 * @return Pointer to trimmed string
 */
char* trim_whitespace(char *str);

/**
 * Parse boolean value from string
 * @param str Input string ("true", "false", "1", "0", "yes", "no")
 * @return 1 for true, 0 for false, -1 for invalid
 */
int parse_boolean(const char *str);

/**
 * Get random bytes
 * @param buffer Buffer to store random bytes
 * @param length Number of bytes to generate
 * @return 0 on success, -1 on error
 */
int get_random_bytes(uint8_t *buffer, size_t length);

/**
 * Calculate CRC32 checksum
 * @param data Data buffer
 * @param length Data length
 * @return CRC32 checksum
 */
uint32_t crc32(const uint8_t *data, size_t length);

/**
 * Sleep for specified milliseconds
 * @param milliseconds Sleep duration
 */
void sleep_ms(uint32_t milliseconds);

/**
 * Get monotonic time in milliseconds
 * @return Time in milliseconds since some unspecified starting point
 */
uint64_t get_monotonic_time_ms(void);

/**
 * Check if file exists
 * @param filepath Path to file
 * @return 1 if exists, 0 otherwise
 */
int file_exists(const char *filepath);

/**
 * Create directory recursively
 * @param path Directory path
 * @return 0 on success, -1 on error
 */
int create_directory(const char *path);

/**
 * Get file size
 * @param filepath Path to file
 * @return File size in bytes, -1 on error
 */
long get_file_size(const char *filepath);

#endif /* UTILS_H */
