#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include "mqtt_broker.h"
#include "utils.h"

static mqtt_broker_t g_broker;
static volatile int g_running = 1;

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\n");
    printf("Lightweight MQTT Broker v%s\n", MQTT_BROKER_VERSION);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config FILE     Configuration file (default: config.json)\n");
    printf("  -p, --port PORT       TCP port to listen on (default: 1883)\n");
    printf("  -s, --ssl-port PORT   SSL port to listen on (default: 8883)\n");
    printf("  -b, --bind ADDR       Address to bind to (default: 0.0.0.0)\n");
    printf("  -l, --log-level LEVEL Log level: 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG (default: 2)\n");
    printf("  -f, --log-file FILE   Log file path (default: console only)\n");
    printf("  -d, --daemon          Run as daemon\n");
    printf("  -v, --version         Show version information\n");
    printf("  -h, --help            Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c broker.json\n", program_name);
    printf("  %s -p 1883 -s 8883 -l 3\n", program_name);
    printf("  %s --daemon --log-file /var/log/mqtt.log\n", program_name);
    printf("\n");
}

static void print_version(void) {
    printf("MQTT Broker %s\n", MQTT_BROKER_VERSION);
    printf("Built: %s %s\n", __DATE__, __TIME__);
    printf("Features: SSL/TLS, JSON Config, Static Linking\n");
    printf("Target: Embedded Linux Systems\n");
}

static void signal_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    g_running = 0;
    exit(EXIT_FAILURE);
}

static void setup_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    // Ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
}

static void print_startup_info(mqtt_broker_t *broker) {
    LOG_INFO("=== MQTT Broker %s ===", MQTT_BROKER_VERSION);
    LOG_INFO("TCP Port:     %d", broker->config.port);
    if (broker->config.ssl_enabled) {
        LOG_INFO("SSL Port:     %d", broker->config.ssl_port);
    }
    LOG_INFO("Bind Address: %s", broker->config.bind_address);
    LOG_INFO("Max Clients:  %d", broker->config.max_clients);
    LOG_INFO("Log Level:    %d", broker->config.log_level);
    LOG_INFO("Anonymous:    %s", broker->config.allow_anonymous ? "yes" : "no");
    LOG_INFO("SSL/TLS:      %s", broker->config.ssl_enabled ? "yes" : "no");
    
    // Memory info
    char memory_str[64];
    format_bytes(broker->config.memory_limit, memory_str, sizeof(memory_str));
    LOG_INFO("Memory Limit: %s", memory_str);
    
    long current_memory = get_memory_usage();
    if (current_memory > 0) {
        format_bytes(current_memory, memory_str, sizeof(memory_str));
        LOG_INFO("Current RAM:  %s", memory_str);
    }
    
    LOG_INFO("=========================");
    LOG_INFO("MQTT broker starting up...");
}

static void print_shutdown_info(mqtt_broker_t *broker) {
    uint64_t uptime, total_messages;
    uint32_t active_clients;
    mqtt_broker_get_stats(broker, &uptime, &active_clients, &total_messages);
    
    LOG_INFO("=== MQTT Broker Shutdown ===");
    LOG_INFO("Uptime:        %lu seconds", uptime);
    LOG_INFO("Total Messages: %lu", total_messages);
    LOG_INFO("Total Clients:  %lu", broker->total_clients);
    LOG_INFO("Active Clients: %u", active_clients);
    
    long final_memory = get_memory_usage();
    if (final_memory > 0) {
        char memory_str[64];
        format_bytes(final_memory, memory_str, sizeof(memory_str));
        LOG_INFO("Final Memory:  %s", memory_str);
    }
    
    LOG_INFO("=============================");
    LOG_INFO("MQTT broker shutdown completed");
}

static int daemonize(void) {
    pid_t pid = fork();
    
    if (pid < 0) {
        LOG_ERROR("Failed to fork daemon: %s", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        // Parent process exits
        exit(0);
    }
    
    // Child process continues
    if (setsid() < 0) {
        LOG_ERROR("Failed to create new session: %s", strerror(errno));
        return -1;
    }
    
    // Second fork to prevent acquiring controlling terminal
    pid = fork();
    if (pid < 0) {
        LOG_ERROR("Failed to fork daemon (second): %s", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    // Change working directory to root
    if (chdir("/") < 0) {
        LOG_ERROR("Failed to change directory to /: %s", strerror(errno));
        return -1;
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    return 0;
}

int main(int argc, char *argv[]) {
    const char *config_file = "config.json";
    const char *log_file = NULL;
    int custom_port = -1;
    int custom_ssl_port = -1;
    const char *custom_bind_addr = NULL;
    int custom_log_level = -1;
    int daemon_mode = 0;
    
    static struct option long_options[] = {
        {"config",    required_argument, 0, 'c'},
        {"port",      required_argument, 0, 'p'},
        {"ssl-port",  required_argument, 0, 's'},
        {"bind",      required_argument, 0, 'b'},
        {"log-level", required_argument, 0, 'l'},
        {"log-file",  required_argument, 0, 'f'},
        {"daemon",    no_argument,       0, 'd'},
        {"version",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "c:p:s:b:l:f:dvh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'p':
                custom_port = atoi(optarg);
                if (custom_port <= 0 || custom_port > 65535) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return 1;
                }
                break;
            case 's':
                custom_ssl_port = atoi(optarg);
                if (custom_ssl_port <= 0 || custom_ssl_port > 65535) {
                    fprintf(stderr, "Invalid SSL port: %s\n", optarg);
                    return 1;
                }
                break;
            case 'b':
                custom_bind_addr = optarg;
                break;
            case 'l':
                custom_log_level = atoi(optarg);
                if (custom_log_level < 0 || custom_log_level > 3) {
                    fprintf(stderr, "Invalid log level: %s (must be 0-3)\n", optarg);
                    return 1;
                }
                break;
            case 'f':
                log_file = optarg;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'v':
                print_version();
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize broker
    memset(&g_broker, 0, sizeof(g_broker));
    
    if (mqtt_broker_init(&g_broker, config_file) != 0) {
        fprintf(stderr, "Failed to initialize MQTT broker\n");
        return 1;
    }
    
    // Apply command line overrides
    if (custom_port > 0) {
        g_broker.config.port = custom_port;
    }
    if (custom_ssl_port > 0) {
        g_broker.config.ssl_port = custom_ssl_port;
    }
    if (custom_bind_addr) {
        safe_strncpy(g_broker.config.bind_address, custom_bind_addr, 
                    sizeof(g_broker.config.bind_address));
    }
    if (custom_log_level >= 0) {
        g_broker.config.log_level = custom_log_level;
    }
    if (log_file) {
        safe_strncpy(g_broker.config.log_file, log_file, 
                    sizeof(g_broker.config.log_file));
    }
    
    // Initialize logging
    if (log_init(strlen(g_broker.config.log_file) > 0 ? g_broker.config.log_file : NULL,
                 g_broker.config.log_level, 
                 daemon_mode ? 0 : g_broker.config.log_to_console) != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        mqtt_broker_cleanup(&g_broker);
        return 1;
    }
    
    // Daemonize if requested
    if (daemon_mode) {
        if (daemonize() != 0) {
            mqtt_broker_cleanup(&g_broker);
            log_cleanup();
            return 1;
        }
    }
    
    // Setup signal handlers
    setup_signal_handlers();
    
    // Print startup information
    if (!daemon_mode) {
        print_startup_info(&g_broker);
    }
    
    // Validate configuration
    if (config_validate(&g_broker.config) != 0) {
        LOG_ERROR("Configuration validation failed");
        mqtt_broker_cleanup(&g_broker);
        log_cleanup();
        return 1;
    }
    
    LOG_INFO("MQTT broker initialized successfully");
    
    // Main broker loop
    int exit_code = 0;
    if (mqtt_broker_run(&g_broker) != 0) {
        LOG_ERROR("Broker main loop failed");
        exit_code = 1;
    }
    
    // Shutdown
    if (!daemon_mode) {
        print_shutdown_info(&g_broker);
    }
    
    mqtt_broker_cleanup(&g_broker);
    log_cleanup();
    
    return exit_code;
}
