/**
 * @file topic_tree.c
 * @brief Topic tree for MQTT broker
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "topic_tree.h"
#include "session.h"
#include "logger.h"
#include "utils.h"
#include "persistence.h"

// Topic node subscription structure
typedef struct topic_subscription {
    session_t *session;
    int qos;
    struct topic_subscription *next;
} topic_subscription_t;

// Topic node structure
struct topic_node {
    char *name;
    struct topic_node *parent;
    struct topic_node *children;
    struct topic_node *next_sibling;
    topic_subscription_t *subscriptions;
    void *retained_message;
    size_t retained_message_len;
    int retained_qos;
};

// Global topic tree state
static topic_node_t *root = NULL;
static int initialized = 0;

// Forward declarations
static void topic_node_free(topic_node_t *node);
static topic_node_t *topic_node_find_or_create(const char *topic);
static topic_node_t *topic_node_find(const char *topic);
static void topic_node_publish(topic_node_t *node, const char *topic, const void *payload, size_t payload_len, int qos, int retain);
static void topic_node_unsubscribe_session(topic_node_t *node, session_t *session);

int topic_tree_init(void) {
    if (initialized) {
        return 0;
    }
    
    // Create root node
    root = (topic_node_t *)calloc(1, sizeof(topic_node_t));
    if (!root) {
        log_error("Failed to allocate memory for topic tree root");
        return -1;
    }
    
    root->name = utils_strdup("");
    if (!root->name) {
        free(root);
        root = NULL;
        log_error("Failed to allocate memory for topic tree root name");
        return -1;
    }
    
    initialized = 1;
    log_info("Topic tree initialized");
    
    return 0;
}

void topic_tree_cleanup(void) {
    if (!initialized) {
        return;
    }
    
    topic_node_free(root);
    root = NULL;
    initialized = 0;
}

int topic_tree_subscribe(const char *topic, session_t *session, int qos) {
    topic_node_t *node;
    topic_subscription_t *subscription, *prev, *current;
    
    if (!initialized || !topic || !session) {
        log_error("Invalid parameters for topic_tree_subscribe: initialized=%d, topic=%p, session=%p", 
                 initialized, topic, session);
        return -1;
    }
    
    const char *client_id = session_get_client_id(session);
    int socket = session_get_socket(session);
    
    log_debug("Processing subscription request: Topic='%s', Client ID='%s', Socket=%d, QoS=%d", 
             topic, client_id ? client_id : "UNKNOWN", socket, qos);
             
    // Check socket validity
    if (socket <= 0) {
        log_error("Invalid socket (%d) for client %s, cannot add subscription", 
                 socket, client_id ? client_id : "UNKNOWN");
        return -1;
    }
    
    // Find or create the topic node
    node = topic_node_find_or_create(topic);
    if (!node) {
        log_error("Failed to find or create topic node: %s", topic);
        return -1;
    }
    
    log_debug("Found/created topic node '%s' for subscription", 
             node->name ? node->name : "ROOT");
    
    // Check if the session is already subscribed
    int sub_index = 0;
    for (subscription = node->subscriptions; subscription; subscription = subscription->next) {
        session_t *sub_session = subscription->session;
        const char *sub_client_id = sub_session ? session_get_client_id(sub_session) : "NULL";
        
        log_debug("Checking existing subscription #%d: Client ID=%s, Session=%p", 
                 sub_index++, sub_client_id ? sub_client_id : "NULL", sub_session);
        
        if (subscription->session == session) {
            // Update QoS
            log_debug("Client %s already subscribed to topic %s, updating QoS from %d to %d", 
                     client_id, topic, subscription->qos, qos);
            subscription->qos = qos;
            return 0;
        }
    }
    
    // Create new subscription
    subscription = (topic_subscription_t *)calloc(1, sizeof(topic_subscription_t));
    if (!subscription) {
        log_error("Failed to allocate memory for topic subscription");
        return -1;
    }
    
    subscription->session = session;
    subscription->qos = qos;
    
    log_debug("Created new subscription for client %s to topic %s with QoS %d", 
             client_id, topic, qos);
    
    // Add to the subscription list (no particular order)
    if (!node->subscriptions) {
        node->subscriptions = subscription;
        log_debug("Added as first subscription to node '%s'", node->name ? node->name : "ROOT");
    } else {
        // Find the end of the list
        prev = NULL;
        current = node->subscriptions;
        
        while (current) {
            prev = current;
            current = current->next;
        }
        
        // Add to the end
        prev->next = subscription;
        log_debug("Added as %dth subscription to node '%s'", sub_index + 1, node->name ? node->name : "ROOT");
    }
    
    // Add to the session
    if (session_add_subscription(session, topic, qos) != 0) {
        // Failed to add to session, clean up
        if (node->subscriptions == subscription) {
            node->subscriptions = subscription->next;
        } else {
            prev = NULL;
            current = node->subscriptions;
            
            while (current && current != subscription) {
                prev = current;
                current = current->next;
            }
            
            if (current && prev) {
                prev->next = current->next;
            }
        }
        
        free(subscription);
        log_error("Failed to add subscription to session");
        return -1;
    }
    
    log_debug("Session %s subscribed to topic: %s (QoS %d)", session_get_client_id(session), topic, qos);
    
    // Check if there's a retained message
    if (node->retained_message) {
        // Publish the retained message to the session
        log_debug("Publishing retained message to new subscriber");
        topic_node_publish(node, topic, node->retained_message, node->retained_message_len, node->retained_qos, 1);
    }
    
    return 0;
}

int topic_tree_unsubscribe(const char *topic, session_t *session) {
    topic_node_t *node;
    topic_subscription_t *subscription, *prev = NULL;
    
    if (!initialized || !topic || !session) {
        return -1;
    }
    
    // Find the topic node
    node = topic_node_find(topic);
    if (!node) {
        log_debug("Topic not found: %s", topic);
        return -1;
    }
    
    // Find the subscription
    for (subscription = node->subscriptions; subscription; prev = subscription, subscription = subscription->next) {
        if (subscription->session == session) {
            // Remove from list
            if (prev) {
                prev->next = subscription->next;
            } else {
                node->subscriptions = subscription->next;
            }
            
            // Free the subscription
            free(subscription);
            
            // Remove from session
            session_remove_subscription(session, topic);
            
            log_debug("Session %s unsubscribed from topic: %s", session_get_client_id(session), topic);
            return 0;
        }
    }
    
    log_debug("Session %s not subscribed to topic: %s", session_get_client_id(session), topic);
    return -1;
}

int topic_tree_unsubscribe_all(session_t *session) {
    if (!initialized || !session) {
        return -1;
    }
    
    // Unsubscribe from all topics
    topic_node_unsubscribe_session(root, session);
    
    return 0;
}

// Forward declaration for new recursive publish function
static void topic_tree_publish_recursive(topic_node_t *node, const char *topic_part, const char *full_topic, const void *payload, size_t payload_len, int qos, int retain);

int topic_tree_publish(const char *topic, const void *payload, size_t payload_len, int qos, int retain) {
    topic_node_t *node;
    
    if (!initialized || !topic || !payload) {
        log_error("Invalid parameters for topic_tree_publish: initialized=%d, topic=%p, payload=%p", 
                 initialized, topic, payload);
        return -1;
    }
    
    log_debug("Publishing to topic tree: %s (payload: %zu bytes, QoS: %d, retain: %d)", 
              topic, payload_len, qos, retain);
    
    // Find or create the topic node for the exact topic (for direct matches and retained messages)
    node = topic_node_find_or_create(topic);
    if (!node) {
        log_error("Failed to find or create topic node: %s", topic);
        return -1;
    }
    
    log_debug("Found/created topic node for publishing: %s", topic);
    
    // Handle retained message
    if (retain) {
        log_debug("Storing retained message for topic: %s", topic);
        // Free any existing retained message
        free(node->retained_message);
        
        // Store the new retained message
        node->retained_message = utils_memdup(payload, payload_len);
        if (!node->retained_message) {
            log_error("Failed to allocate memory for retained message");
            return -1;
        }
        
        node->retained_message_len = payload_len;
        node->retained_qos = qos;
        
        // Save to persistence
        persistence_save_message("", topic, payload, payload_len, qos, retain);
        log_debug("Retained message stored and persisted for topic: %s", topic);
    } else if (node->retained_message && payload_len == 0) {
        // A zero-length payload indicates that the retained message should be cleared
        log_debug("Clearing retained message for topic: %s", topic);
        free(node->retained_message);
        node->retained_message = NULL;
        node->retained_message_len = 0;
        
        // Save to persistence (with empty payload to indicate clearing)
        persistence_save_message("", topic, "", 0, 0, 1);
        log_debug("Retained message cleared for topic: %s", topic);
    }
    
    // First publish to direct subscribers at this exact node
    log_debug("Publishing to exact match subscribers for topic: %s", topic);
    topic_node_publish(node, topic, payload, payload_len, qos, retain);
    
    // Next, start a recursive search from the root to handle wildcards
    log_debug("Starting recursive wildcard match for topic: %s", topic);
    topic_tree_publish_recursive(root, topic, topic, payload, payload_len, qos, retain);
    
    log_debug("Completed publish operation for topic: %s", topic);
    
    return 0;
}

// Free a topic node and all its children
static void topic_node_free(topic_node_t *node) {
    topic_node_t *child, *next_child;
    topic_subscription_t *subscription, *next_subscription;
    
    if (!node) {
        return;
    }
    
    // Free children
    child = node->children;
    while (child) {
        next_child = child->next_sibling;
        topic_node_free(child);
        child = next_child;
    }
    
    // Free subscriptions
    subscription = node->subscriptions;
    while (subscription) {
        next_subscription = subscription->next;
        free(subscription);
        subscription = next_subscription;
    }
    
    // Free retained message
    free(node->retained_message);
    
    // Free node
    free(node->name);
    free(node);
}

// Find or create a topic node
static topic_node_t *topic_node_find_or_create(const char *topic) {
    char *topic_copy, *token, *saveptr;
    topic_node_t *node, *prev, *child;
    
    if (!topic) {
        return NULL;
    }
    
    // Start at the root
    node = root;
    
    // Empty topic
    if (!*topic) {
        return node;
    }
    
    // Make a copy of the topic string
    topic_copy = utils_strdup(topic);
    if (!topic_copy) {
        log_error("Failed to allocate memory for topic copy");
        return NULL;
    }
    
    // Split the topic into tokens
    token = strtok_r(topic_copy, "/", &saveptr);
    
    while (token) {
        // Look for the token in the children
        prev = NULL;
        child = node->children;
        
        while (child) {
            if (strcmp(child->name, token) == 0) {
                // Found it
                break;
            }
            
            prev = child;
            child = child->next_sibling;
        }
        
        if (!child) {
            // Token not found, create a new node
            child = (topic_node_t *)calloc(1, sizeof(topic_node_t));
            if (!child) {
                free(topic_copy);
                log_error("Failed to allocate memory for topic node");
                return NULL;
            }
            
            child->name = utils_strdup(token);
            if (!child->name) {
                free(child);
                free(topic_copy);
                log_error("Failed to allocate memory for topic node name");
                return NULL;
            }
            
            child->parent = node;
            
            // Add to the children list
            if (!node->children) {
                node->children = child;
            } else {
                prev->next_sibling = child;
            }
        }
        
        // Move to the next level
        node = child;
        
        // Next token
        token = strtok_r(NULL, "/", &saveptr);
    }
    
    free(topic_copy);
    return node;
}

// Find a topic node
static topic_node_t *topic_node_find(const char *topic) {
    char *topic_copy, *token, *saveptr;
    topic_node_t *node, *child;
    
    if (!topic) {
        return NULL;
    }
    
    // Start at the root
    node = root;
    
    // Empty topic
    if (!*topic) {
        return node;
    }
    
    log_debug("Searching for topic node: %s", topic);
    
    // Make a copy of the topic string
    topic_copy = utils_strdup(topic);
    if (!topic_copy) {
        log_error("Failed to allocate memory for topic copy");
        return NULL;
    }
    
    // Split the topic into tokens
    token = strtok_r(topic_copy, "/", &saveptr);
    
    while (token) {
        // Look for the token in the children
        child = node->children;
        
        log_debug("Looking for token '%s' at level with parent '%s'", 
                 token, node->name ? node->name : "ROOT");
        
        while (child) {
            if (strcmp(child->name, token) == 0) {
                // Found it
                log_debug("Found matching child node: %s", child->name);
                break;
            }
            
            child = child->next_sibling;
        }
        
        if (!child) {
            // Token not found
            log_debug("Token '%s' not found in topic tree", token);
            free(topic_copy);
            return NULL;
        }
        
        // Move to the next level
        node = child;
        
        // Next token
        token = strtok_r(NULL, "/", &saveptr);
    }
    
    log_debug("Found topic node for: %s", topic);
    free(topic_copy);
    return node;
}

// Count the number of subscriptions in a list
static int count_subscriptions(topic_subscription_t *list) {
    int count = 0;
    topic_subscription_t *sub;
    
    for (sub = list; sub != NULL; sub = sub->next) {
        count++;
    }
    
    return count;
}

// Publish a message to all subscribers of a node
static void topic_node_publish(topic_node_t *node, const char *topic, const void *payload, size_t payload_len, int qos, int retain) {
    topic_subscription_t *subscription;
    
    if (!node || !topic || !payload) {
        log_error("Invalid parameters for topic_node_publish: node=%p, topic=%p, payload=%p", 
                 node, topic, payload);
        return;
    }
    
    // Publish to all subscribers of this node
    int subscriber_count = count_subscriptions(node->subscriptions);
    log_debug("Node '%s' has %d subscribers", 
              node->name ? node->name : "ROOT", 
              subscriber_count);
              
    if (subscriber_count == 0) {
        log_debug("No subscribers found for node '%s'", node->name ? node->name : "ROOT");
    } else {
        log_debug("Found %d subscribers for node '%s', preparing to publish", 
                 subscriber_count, node->name ? node->name : "ROOT");
        
        // List subscription details for debugging
        int sub_index = 0;
        for (subscription = node->subscriptions; subscription; subscription = subscription->next) {
            session_t *sess = subscription->session;
            const char *cid = sess ? session_get_client_id(sess) : "NULL";
            int sock = sess ? session_get_socket(sess) : -1;
            
            log_debug("  Subscription #%d: client_id=%s, socket=%d, qos=%d, session=%p", 
                     sub_index++, cid ? cid : "NULL", sock, subscription->qos, sess);
        }
    }
    
    int forward_count = 0;
    int success_count = 0;
    
    for (subscription = node->subscriptions; subscription; subscription = subscription->next) {
        // Use the lower QoS of the subscriber and the message
        int subscriber_qos = subscription->qos;
        int effective_qos = qos < subscriber_qos ? qos : subscriber_qos;
        
        // Get the actual session
        session_t *session = subscription->session;
        forward_count++;
        
        if (session) {
            const char *client_id = session_get_client_id(session);
            int socket = session_get_socket(session);
            
            log_debug("Attempting to forward message on topic '%s' to subscriber '%s' (QoS %d, socket %d)", 
                     topic, client_id ? client_id : "UNKNOWN", effective_qos, socket);
            
            // Check session validity
            if (socket <= 0) {
                log_error("Invalid socket (%d) for client %s, skipping message forwarding", 
                         socket, client_id ? client_id : "UNKNOWN");
                continue;
            }
            
            if (session_forward_message(session, topic, payload, payload_len, effective_qos) == 0) {
                log_info("Message forwarded successfully to %s for topic %s", 
                        client_id ? client_id : "UNKNOWN", topic);
                success_count++;
            } else {
                log_error("Failed to forward message to %s for topic %s (socket %d)", 
                         client_id ? client_id : "UNKNOWN", topic, socket);
            }
        } else {
            log_warn("Subscription has no associated session, removing invalid subscription");
            // We should remove this invalid subscription in a real implementation
        }
    }
    
    log_debug("Forwarding summary for topic '%s': attempted=%d, succeeded=%d", 
             topic, forward_count, success_count);
}

// Recursive function to match topics against the subscription tree and deliver messages
static void topic_tree_publish_recursive(topic_node_t *node, const char *topic_part, const char *full_topic, const void *payload, size_t payload_len, int qos, int retain) {
    topic_node_t *child;
    char *topic_copy, *next_token, *saveptr;
    
    if (!node || !topic_part || !*topic_part || !full_topic || !payload) {
        return;
    }
    
    // Check for single-level wildcard ("+") among subscribers at this level
    // These would include subscriptions to topics like "a/+/c" that match our topic "a/b/c"
    for (child = node->children; child; child = child->next_sibling) {
        if (strcmp(child->name, "+") == 0) {
            log_debug("Found matching '+' wildcard at level in topic tree");
            
            // Check if we're at the last part of the topic
            topic_copy = utils_strdup(topic_part);
            if (!topic_copy) {
                log_error("Failed to duplicate topic part");
                return;
            }
            
            // Get the next token after the current one
            strtok_r(topic_copy, "/", &saveptr);
            next_token = strtok_r(NULL, "/", &saveptr);
            
            if (next_token) {
                // There are more parts of the topic, continue traversing with wildcard node
                topic_tree_publish_recursive(child, next_token, full_topic, payload, payload_len, qos, retain);
            } else {
                // This is the leaf level, publish to subscribers of the wildcard node
                topic_node_publish(child, full_topic, payload, payload_len, qos, retain);
            }
            
            free(topic_copy);
        }
    }
    
    // Check for multi-level wildcard ("#") among subscribers at this level
    // These would match any topic topic that starts with the path up to the "#"
    for (child = node->children; child; child = child->next_sibling) {
        if (strcmp(child->name, "#") == 0) {
            log_debug("Found matching '#' wildcard in topic tree, publishing message");
            // The "#" wildcard matches all topics at this level and below
            topic_node_publish(child, full_topic, payload, payload_len, qos, retain);
        }
    }
    
    // Now proceed to exact matches
    topic_copy = utils_strdup(topic_part);
    if (!topic_copy) {
        log_error("Failed to duplicate topic part");
        return;
    }
    
    // Get the current token
    char *token = strtok_r(topic_copy, "/", &saveptr);
    if (!token) {
        free(topic_copy);
        return;
    }
    
    // Look for a matching child
    for (child = node->children; child; child = child->next_sibling) {
        if (strcmp(child->name, token) == 0) {
            // We've found an exact match for this level
            next_token = strtok_r(NULL, "/", &saveptr);
            
            if (next_token) {
                // There are more parts of the topic, continue traversing
                topic_tree_publish_recursive(child, next_token, full_topic, payload, payload_len, qos, retain);
            } else {
                // This is the leaf level, publish to subscribers
                topic_node_publish(child, full_topic, payload, payload_len, qos, retain);
            }
            
            break;
        }
    }
    
    free(topic_copy);
}

// Unsubscribe a session from all subscriptions in a node and its children
static void topic_node_unsubscribe_session(topic_node_t *node, session_t *session) {
    topic_node_t *child;
    topic_subscription_t *subscription, *prev, *next;
    
    if (!node || !session) {
        return;
    }
    
    // Unsubscribe from this node
    prev = NULL;
    subscription = node->subscriptions;
    
    while (subscription) {
        next = subscription->next;
        
        if (subscription->session == session) {
            // Remove from list
            if (prev) {
                prev->next = next;
            } else {
                node->subscriptions = next;
            }
            
            // Free the subscription
            free(subscription);
        } else {
            prev = subscription;
        }
        
        subscription = next;
    }
    
    // Unsubscribe from all children
    for (child = node->children; child; child = child->next_sibling) {
        topic_node_unsubscribe_session(child, session);
    }
}

void topic_tree_dump_subscribers(const char *topic) {
    topic_node_t *node;
    topic_subscription_t *subscription;
    int count = 0;
    
    if (!initialized || !topic) {
        log_error("Invalid parameters for topic_tree_dump_subscribers: initialized=%d, topic=%p", 
                 initialized, topic);
        return;
    }
    
    log_debug("Dumping subscribers for topic: %s", topic);
    
    // Find the topic node
    node = topic_node_find(topic);
    if (!node) {
        log_debug("Topic node not found: %s", topic);
        return;
    }
    
    log_debug("Found topic node '%s', checking subscribers", node->name ? node->name : "ROOT");
    
    // Count and dump subscribers
    count = count_subscriptions(node->subscriptions);
    if (count == 0) {
        log_debug("No subscribers found for topic: %s", topic);
        return;
    }
    
    log_debug("Topic %s has %d subscribers:", topic, count);
    
    // List each subscriber
    int sub_index = 0;
    for (subscription = node->subscriptions; subscription; subscription = subscription->next) {
        session_t *session = subscription->session;
        const char *client_id = session ? session_get_client_id(session) : "NULL";
        int socket = session ? session_get_socket(session) : -1;
        
        log_debug("  Subscriber #%d: client_id=%s, socket=%d, qos=%d, session=%p", 
                 sub_index++, client_id ? client_id : "NULL", socket, subscription->qos, session);
    }
}