/**
 * @file utils.h
 * @brief Utility functions for MQTT broker
 */

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

/**
 * Generate a random client ID
 * @param buffer The buffer to store the client ID
 * @param size The size of the buffer
 * @return The buffer pointer on success, NULL on error
 */
char *utils_generate_client_id(char *buffer, size_t size);

/**
 * Check if a topic matches a subscription pattern
 * @param topic The topic to check
 * @param subscription The subscription pattern to check against
 * @return 1 if the topic matches, 0 if not
 */
int utils_topic_matches_subscription(const char *topic, const char *subscription);

/**
 * Duplicate a string (like strdup, but with error handling)
 * @param str The string to duplicate
 * @return A pointer to the duplicated string, or NULL on error
 */
char *utils_strdup(const char *str);

/**
 * Duplicate a memory block
 * @param ptr The memory block to duplicate
 * @param size The size of the memory block
 * @return A pointer to the duplicated memory block, or NULL on error
 */
void *utils_memdup(const void *ptr, size_t size);

/**
 * Convert a string to lowercase
 * @param str The string to convert
 * @return The string pointer
 */
char *utils_strlower(char *str);

/**
 * Convert a string to uppercase
 * @param str The string to convert
 * @return The string pointer
 */
char *utils_strupper(char *str);

/**
 * Trim whitespace from the beginning and end of a string
 * @param str The string to trim
 * @return The string pointer
 */
char *utils_strtrim(char *str);

/**
 * Split a string into tokens
 * @param str The string to split
 * @param delim The delimiter character
 * @param tokens The array to store the tokens
 * @param max_tokens The maximum number of tokens to store
 * @return The number of tokens found
 */
int utils_strsplit(const char *str, char delim, char **tokens, int max_tokens);

/**
 * Join tokens into a string
 * @param tokens The array of tokens
 * @param token_count The number of tokens
 * @param delim The delimiter character
 * @param result The buffer to store the result
 * @param result_size The size of the result buffer
 * @return The result buffer pointer on success, NULL on error
 */
char *utils_strjoin(char **tokens, int token_count, char delim, char *result, size_t result_size);

/**
 * URL encode a string
 * @param str The string to encode
 * @param result The buffer to store the result
 * @param result_size The size of the result buffer
 * @return The result buffer pointer on success, NULL on error
 */
char *utils_url_encode(const char *str, char *result, size_t result_size);

/**
 * URL decode a string
 * @param str The string to decode
 * @param result The buffer to store the result
 * @param result_size The size of the result buffer
 * @return The result buffer pointer on success, NULL on error
 */
char *utils_url_decode(const char *str, char *result, size_t result_size);

#endif /* UTILS_H */