/**
 * @file logger.c
 * @brief Logging utilities for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "logger.h"

// Global logger state
static FILE *log_file = NULL;
static log_level_t log_level = LOG_LEVEL_INFO;
static int initialized = 0;

// Level strings
static const char *level_strings[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

int log_init(log_level_t level, const char *file_path) {
    if (initialized) {
        return 0;
    }
    
    log_level = level;
    
    if (file_path) {
        log_file = fopen(file_path, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", file_path);
            return -1;
        }
    } else {
        log_file = stdout;
    }
    
    initialized = 1;
    
    log_info("Logger initialized with level %s", level_strings[level]);
    return 0;
}

void log_cleanup(void) {
    if (!initialized) {
        return;
    }
    
    if (log_file && log_file != stdout) {
        fclose(log_file);
        log_file = NULL;
    }
    
    initialized = 0;
}

void log_set_level(log_level_t level) {
    log_level = level;
    
    if (initialized) {
        log_info("Log level set to %s", level_strings[level]);
    }
}

// Generic log function
static void log_message(log_level_t level, const char *format, va_list args) {
    time_t now;
    struct tm *time_info;
    char time_str[20];
    
    if (!initialized) {
        // Not initialized, use stderr
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
        return;
    }
    
    if (level < log_level) {
        // Skip messages below the current log level
        return;
    }
    
    // Get current time
    time(&now);
    time_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);
    
    // Print log message
    fprintf(log_file, "[%s] [%s] ", time_str, level_strings[level]);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");
    
    // Flush the log file
    fflush(log_file);
}

void log_debug(const char *format, ...) {
    va_list args;
    
    va_start(args, format);
    log_message(LOG_LEVEL_DEBUG, format, args);
    va_end(args);
}

void log_info(const char *format, ...) {
    va_list args;
    
    va_start(args, format);
    log_message(LOG_LEVEL_INFO, format, args);
    va_end(args);
}

void log_warn(const char *format, ...) {
    va_list args;
    
    va_start(args, format);
    log_message(LOG_LEVEL_WARN, format, args);
    va_end(args);
}

void log_error(const char *format, ...) {
    va_list args;
    
    va_start(args, format);
    log_message(LOG_LEVEL_ERROR, format, args);
    va_end(args);
}

void log_fatal(const char *format, ...) {
    va_list args;
    
    va_start(args, format);
    log_message(LOG_LEVEL_FATAL, format, args);
    va_end(args);
}