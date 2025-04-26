/**
 * @file logger.h
 * @brief Logging utilities for MQTT broker
 */

#ifndef LOGGER_H
#define LOGGER_H

/**
 * Log levels
 */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_t;

/**
 * Initialize the logger
 * @param level The log level
 * @param log_file The log file, or NULL for stdout
 * @return 0 on success, non-zero on error
 */
int log_init(log_level_t level, const char *log_file);

/**
 * Clean up the logger
 */
void log_cleanup(void);

/**
 * Set the log level
 * @param level The log level
 */
void log_set_level(log_level_t level);

/**
 * Log a debug message
 * @param format The format string
 * @param ... The format arguments
 */
void log_debug(const char *format, ...);

/**
 * Log an info message
 * @param format The format string
 * @param ... The format arguments
 */
void log_info(const char *format, ...);

/**
 * Log a warning message
 * @param format The format string
 * @param ... The format arguments
 */
void log_warn(const char *format, ...);

/**
 * Log an error message
 * @param format The format string
 * @param ... The format arguments
 */
void log_error(const char *format, ...);

/**
 * Log a fatal message
 * @param format The format string
 * @param ... The format arguments
 */
void log_fatal(const char *format, ...);

#endif /* LOGGER_H */