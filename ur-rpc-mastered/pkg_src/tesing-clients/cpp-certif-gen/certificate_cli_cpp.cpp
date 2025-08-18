/*
 * C++ Certificate Generation CLI Application
 * 
 * This application demonstrates the C++ wrapper around the cert_manager API
 * and performs the same operations as ssl_tls_main.c, generating both
 * generic and client-specific certificates using modern C++ features.
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <iomanip>
#include <algorithm>
#include <getopt.h>
#include <csignal>

#include "CertificateManager.hpp"

using namespace CertificateAPI;
using CertificateAPI::AppConfig;

// Global variables for signal handling
static volatile bool g_running = true;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "\n[INFO] Received signal " << signum << ", shutting down gracefully..." << std::endl;
    g_running = false;
}

// Setup signal handlers
void setupSignalHandlers() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
}

// Enhanced command line options structure
struct CLIOptions {
    std::string clientId;
    std::string commonName = "mqtt-client-cpp";
    std::string organization = "TestOrgCPP";
    int validityDays = 365;
    bool verbose = false;
    bool help = false;
    bool generateBoth = true;
    bool generateGeneric = false;
    bool generateClientSpecific = false;
    bool testConnections = true;
    std::string configFile;
    bool saveConfig = false;
    
    CLIOptions() = default;
};

// Print usage information
void printUsage(const char* programName) {
    std::cout << "C++ Certificate Generation CLI Application\n"
              << "==========================================\n"
              << "Usage: " << programName << " [options]\n\n"
              << "Configuration Options:\n"
              << "  -f, --config FILE       Load configuration from JSON file\n"
              << "  --save-config           Save current configuration to file\n"
              << "  --show-config           Display current configuration\n\n"
              << "Certificate Options:\n"
              << "  -c, --client-id ID      Set custom client ID (default: auto-generated)\n"
              << "  -o, --org ORG           Set organization name\n"
              << "  -n, --cn CN             Set common name\n"
              << "  -d, --days DAYS         Set validity days\n"
              << "  -g, --generic-only      Generate only generic certificates\n"
              << "  -s, --specific-only     Generate only client-specific certificates\n\n"
              << "Connection Options:\n"
              << "  -H, --host HOST         MQTT broker host\n"
              << "  -P, --port PORT         MQTT broker port\n"
              << "  -C, --ca-cert FILE      CA certificate file path\n"
              << "  -e, --client-cert FILE  Client certificate file path\n"
              << "  -k, --client-key FILE   Client private key file path\n"
              << "  -O, --output-dir DIR    Certificate output directory\n\n"
              << "Runtime Options:\n"
              << "  -v, --verbose           Enable verbose output\n"
              << "  -t, --no-test           Skip SSL connection testing\n"
              << "  -h, --help              Show this help message\n\n"
              << "This C++ application supports JSON configuration files for easy setup.\n"
              << "CLI arguments override configuration file settings.\n\n"
              << "Examples:\n"
              << "  " << programName << " --config cert_config.json\n"
              << "  " << programName << " --client-id my_client --org \"My Company\"\n"
              << "  " << programName << " --generic-only --verbose --no-test\n"
              << "  " << programName << " --host localhost --port 1883 --no-ssl\n";
}

// Parse command line arguments
CLIOptions parseCommandLine(int argc, char* argv[]) {
    CLIOptions options;
    bool showConfig = false;
    
    static struct option longOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"verbose", no_argument, nullptr, 'v'},
        {"client-id", required_argument, nullptr, 'c'},
        {"org", required_argument, nullptr, 'o'},
        {"cn", required_argument, nullptr, 'n'},
        {"days", required_argument, nullptr, 'd'},
        {"generic-only", no_argument, nullptr, 'g'},
        {"specific-only", no_argument, nullptr, 's'},
        {"no-test", no_argument, nullptr, 't'},
        {"config", required_argument, nullptr, 'f'},
        {"save-config", no_argument, nullptr, 1001},
        {"show-config", no_argument, nullptr, 1002},
        {nullptr, 0, nullptr, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "hvc:o:n:d:gstf:", longOptions, nullptr)) != -1) {
        switch (c) {
            case 'h':
                options.help = true;
                break;
            case 'v':
                options.verbose = true;
                break;
            case 'c':
                options.clientId = optarg;
                break;
            case 'o':
                options.organization = optarg;
                break;
            case 'n':
                options.commonName = optarg;
                break;
            case 'd':
                options.validityDays = std::stoi(optarg);
                break;
            case 'g':
                options.generateGeneric = true;
                options.generateBoth = false;
                break;
            case 's':
                options.generateClientSpecific = true;
                options.generateBoth = false;
                break;
            case 't':
                options.testConnections = false;
                break;
            case 'f':
                options.configFile = optarg;
                break;
            case 1001:
                options.saveConfig = true;
                break;
            case 1002:
                showConfig = true;
                break;
            case '?':
                throw std::runtime_error("Invalid command line argument");
        }
    }
    
    // Handle special show-config action
    if (showConfig) {
        AppConfig config;
        if (!options.configFile.empty()) {
            config = CertificateManager::loadConfigFromFile(options.configFile);
        }
        config = CertificateManager::mergeConfigWithCliArgs(config, argc, argv);
        CertificateManager::printConfiguration(config);
        std::exit(0);
    }
    
    return options;
}

// Create request parameters
RequestParams createRequestParams(const CLIOptions& options, CertificateType certType) {
    RequestParams params;
    params.clientId = options.clientId;
    params.certType = certType;
    params.commonName = options.commonName;
    params.organization = options.organization;
    params.country = "US";
    params.validityDays = options.validityDays;
    params.timestamp = std::chrono::system_clock::now();
    
    return params;
}

// Perform certificate generation with detailed logging
Status performCertificateGeneration(CertificateManager& manager,
                                   const CLIOptions& options,
                                   CertificateType certType) {
    
    std::string typeStr = CertificateManager::certificateTypeToString(certType);
    
    std::cout << "\n🔐 === Starting " << typeStr << " certificate generation ===" << std::endl;
    std::cout << "📋 Client ID: " << options.clientId << std::endl;
    std::cout << "📋 Common Name: " << options.commonName << std::endl;
    std::cout << "📋 Organization: " << options.organization << std::endl;
    std::cout << "📋 Validity Days: " << options.validityDays << std::endl;
    
    // Check for existing certificates
    FileInfo fileInfo = manager.checkExistingFiles(options.clientId, certType);
    
    if (fileInfo.exists && fileInfo.valid) {
        std::cout << "ℹ️  Certificate already exists:" << std::endl;
        std::cout << "   📄 Certificate: " << fileInfo.certPath << std::endl;
        std::cout << "   🔑 Private Key: " << fileInfo.keyPath << std::endl;
        
        auto duration = std::chrono::system_clock::now() - fileInfo.creationTime;
        auto hours = std::chrono::duration_cast<std::chrono::hours>(duration).count();
        std::cout << "   ⏰ Created: " << hours << " hours ago" << std::endl;
        std::cout << "ℹ️  Skipping generation for existing certificate." << std::endl;
        return Status::AlreadyExists;
    }
    
    // Create certificate request parameters
    RequestParams params = createRequestParams(options, certType);
    
    // Send certificate request
    Status requestStatus;
    if (certType == CertificateType::Generic) {
        std::cout << "📤 Sending generic certificate request..." << std::endl;
        requestStatus = manager.requestGenericCertificate(params);
    } else {
        std::cout << "📤 Sending client-specific certificate request..." << std::endl;
        requestStatus = manager.requestClientSpecificCertificate(params);
    }
    
    if (requestStatus != Status::Success) {
        std::cout << "❌ Failed to send certificate request: " 
                  << CertificateManager::statusToString(requestStatus) << std::endl;
        return requestStatus;
    }
    
    std::cout << "⏳ Certificate request sent, waiting for response..." << std::endl;
    
    // Wait for response
    Status waitStatus = manager.waitForResponse(30);
    
    if (waitStatus != Status::Success) {
        std::cout << "❌ Failed to receive certificate response: " 
                  << CertificateManager::statusToString(waitStatus) << std::endl;
        return waitStatus;
    }
    
    // Check response status
    const ResponseData& response = manager.getLastResponse();
    if (response.status != Status::Success) {
        std::cout << "❌ Certificate generation failed: " << response.errorMessage << std::endl;
        return response.status;
    }
    
    std::cout << "✅ " << typeStr << " certificate generated successfully!" << std::endl;
    std::cout << "📄 Certificate file: " << response.certFilename << std::endl;
    std::cout << "🔑 Key file: " << response.keyFilename << std::endl;
    
    return Status::Success;
}

// Test SSL connection with generated certificates
Status testSSLConnectionWithCert(CertificateManager& manager, 
                               const std::string& certPath, 
                               const std::string& keyPath) {
    
    std::cout << "\n🔒 === Testing SSL connection with generated certificate ===" << std::endl;
    
    Status sslStatus = manager.testSSLConnection(certPath, keyPath);
    
    if (sslStatus == Status::Success) {
        std::cout << "✅ SSL connection test passed" << std::endl;
    } else {
        std::cout << "❌ SSL connection test failed: " 
                  << CertificateManager::statusToString(sslStatus) << std::endl;
    }
    
    return sslStatus;
}

// Display certificate statistics
void displayCertificateStatistics(CertificateManager& manager, const CLIOptions& options) {
    std::cout << "\n📊 === Certificate Statistics ===" << std::endl;
    
    // Check for generic certificates
    FileInfo genericInfo = manager.checkExistingFiles(options.clientId, CertificateType::Generic);
    if (genericInfo.exists) {
        std::cout << "📄 Generic Certificate: ✅ Found" << std::endl;
        std::cout << "   Path: " << genericInfo.certPath << std::endl;
    } else {
        std::cout << "📄 Generic Certificate: ❌ Not found" << std::endl;
    }
    
    // Check for client-specific certificates
    FileInfo specificInfo = manager.checkExistingFiles(options.clientId, CertificateType::ClientSpecific);
    if (specificInfo.exists) {
        std::cout << "📄 Client-Specific Certificate: ✅ Found" << std::endl;
        std::cout << "   Path: " << specificInfo.certPath << std::endl;
    } else {
        std::cout << "📄 Client-Specific Certificate: ❌ Not found" << std::endl;
    }
}

// Main application logic
int runApplication(const CLIOptions& options, const AppConfig& appConfig) {
    try {
        // Initialize certificate manager with local variable
        auto certManager = std::make_unique<CertificateManager>(options.clientId);
        
        // Set up connection configuration from parsed config
        ConnectionConfig config;
        config.brokerHost = appConfig.brokerHost;
        config.brokerPort = appConfig.brokerPort;
        config.useSSL = appConfig.useSSL;
        config.caCertFile = appConfig.caCertFile;
        config.clientCertFile = appConfig.clientCertFile;
        config.clientKeyFile = appConfig.clientKeyFile;
        
        certManager->setConnectionConfig(config);
        
        std::cout << "🔧 C++ Certificate Manager Configuration:" << std::endl;
        std::cout << "   Client ID: " << options.clientId << std::endl;
        std::cout << "   Broker: " << config.brokerHost << ":" << config.brokerPort << " (SSL)" << std::endl;
        std::cout << "   CA Certificate: " << config.caCertFile << std::endl;
        std::cout << "   Client Certificate: " << config.clientCertFile << std::endl;
        std::cout << "   Client Key: " << config.clientKeyFile << std::endl;
        std::cout << "   Verbose: " << (options.verbose ? "enabled" : "disabled") << std::endl;
        
        // Create certificate directory structure
        Status dirStatus = certManager->createDirectoryStructure();
        if (dirStatus != Status::Success) {
            std::cout << "❌ Failed to create certificate directories: " 
                      << CertificateManager::statusToString(dirStatus) << std::endl;
            return EXIT_FAILURE;
        }
        
        // Initialize and connect
        certManager->initialize();
        certManager->connect();
        
        std::cout << "✅ C++ Certificate manager initialized and connected successfully" << std::endl;
        
        // Perform certificate generation operations
        Status overallStatus = Status::Success;
        Status genericStatus = Status::Success;
        Status specificStatus = Status::Success;
        
        // Generate certificates based on options
        if (options.generateBoth || options.generateGeneric) {
            genericStatus = performCertificateGeneration(*certManager, options, CertificateType::Generic);
            if (genericStatus != Status::Success && genericStatus != Status::AlreadyExists) {
                overallStatus = genericStatus;
            }
        }
        
        if (options.generateBoth || options.generateClientSpecific) {
            specificStatus = performCertificateGeneration(*certManager, options, CertificateType::ClientSpecific);
            if (specificStatus != Status::Success && specificStatus != Status::AlreadyExists) {
                overallStatus = specificStatus;
            }
        }
        
        // Test SSL connections if requested
        if (options.testConnections) {
            if ((genericStatus == Status::Success || genericStatus == Status::AlreadyExists) &&
                (options.generateBoth || options.generateGeneric)) {
                
                std::string genericCert = certManager->generateFilename(options.clientId, CertificateType::Generic, ".crt");
                std::string genericKey = certManager->generateFilename(options.clientId, CertificateType::Generic, ".key");
                
                if (!genericCert.empty() && !genericKey.empty()) {
                    std::string fullCertPath = "generated_certs/" + genericCert;
                    std::string fullKeyPath = "generated_certs/" + genericKey;
                    
                    if (CertificateManager::isFileReadable(fullCertPath) && 
                        CertificateManager::isFileReadable(fullKeyPath)) {
                        testSSLConnectionWithCert(*certManager, fullCertPath, fullKeyPath);
                    }
                }
            }
        }
        
        // Display statistics
        displayCertificateStatistics(*certManager, options);
        
        // Print final summary
        std::cout << "\n📋 === Certificate Generation Summary ===" << std::endl;
        
        if (options.generateBoth || options.generateGeneric) {
            std::cout << "📄 Generic certificate: " 
                      << CertificateManager::statusToString(genericStatus) << std::endl;
        }
        
        if (options.generateBoth || options.generateClientSpecific) {
            std::cout << "📄 Client-specific certificate: " 
                      << CertificateManager::statusToString(specificStatus) << std::endl;
        }
        
        std::cout << "📄 Overall status: " 
                  << CertificateManager::statusToString(overallStatus) << std::endl;
        
        // Determine final result
        bool success = (overallStatus == Status::Success || 
                       (genericStatus == Status::AlreadyExists && specificStatus == Status::AlreadyExists));
        
        if (success) {
            std::cout << "🎉 C++ SSL/TLS certificate generation completed successfully!" << std::endl;
            return EXIT_SUCCESS;
        } else {
            std::cout << "❌ C++ SSL/TLS certificate generation completed with errors" << std::endl;
            return EXIT_FAILURE;
        }
        
    } catch (const CertificateException& e) {
        std::cout << "❌ Certificate exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cout << "❌ Standard exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cout << "❌ Unknown exception occurred" << std::endl;
        return EXIT_FAILURE;
    }
}

// Main function
int main(int argc, char* argv[]) {
    try {
        // Setup signal handlers
        setupSignalHandlers();
        
        // Parse command line arguments
        CLIOptions options = parseCommandLine(argc, argv);
        
        // Show help if requested
        if (options.help) {
            printUsage(argv[0]);
            return EXIT_SUCCESS;
        }
        
        // Load configuration from file if specified
        AppConfig config;
        if (!options.configFile.empty()) {
            std::cout << "📁 Loading configuration from: " << options.configFile << std::endl;
            config = CertificateManager::loadConfigFromFile(options.configFile);
        }
        
        // Merge with CLI arguments (CLI takes precedence)
        config = CertificateManager::mergeConfigWithCliArgs(config, argc, argv);
        
        // Update options with configuration values if not set via CLI
        if (options.clientId.empty()) {
            options.clientId = config.defaultClientId;
        }
        if (options.organization == "TestOrgCPP") {
            options.organization = config.defaultOrganization;
        }
        if (options.commonName == "mqtt-client-cpp") {
            options.commonName = config.defaultCommonName;
        }
        if (options.validityDays == 365) {
            options.validityDays = config.defaultValidityDays;
        }
        if (!options.verbose) {
            options.verbose = config.enableVerbose;
        }
        if (options.testConnections) {
            options.testConnections = config.enableTesting;
        }
        
        // Generate unique client ID if still not provided
        if (options.clientId.empty()) {
            options.clientId = CertificateManager::generateClientId("cpp_client");
        }
        
        // Save configuration if requested
        if (options.saveConfig) {
            std::string configFile = options.configFile.empty() ? "cert_config.json" : options.configFile;
            std::cout << "💾 Saving configuration to: " << configFile << std::endl;
            if (CertificateManager::saveConfigToFile(config, configFile)) {
                std::cout << "✅ Configuration saved successfully" << std::endl;
            } else {
                std::cout << "❌ Failed to save configuration" << std::endl;
            }
        }
        
        std::cout << "🚀 C++ Certificate Generation CLI Application" << std::endl;
        std::cout << "=============================================" << std::endl;
        std::cout << "This application demonstrates the C++ wrapper around cert_manager API" << std::endl;
        std::cout << "and performs both generic and client-specific certificate generation." << std::endl;
        
        if (options.verbose) {
            CertificateManager::printConfiguration(config);
        }
        
        // Run the main application
        return runApplication(options, config);
        
    } catch (const std::exception& e) {
        std::cout << "❌ Application error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cout << "❌ Unknown application error" << std::endl;
        return EXIT_FAILURE;
    }
}