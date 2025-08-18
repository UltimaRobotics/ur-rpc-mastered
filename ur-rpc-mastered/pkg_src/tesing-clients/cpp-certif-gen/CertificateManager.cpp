#include "CertificateManager.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <unistd.h>
#include <getopt.h>
#include <cstdlib>

extern "C" {
    #include <mosquitto.h>
    #include "cJSON.h"
}

namespace CertificateAPI {

    // Exception constructor implementation
    CertificateException::CertificateException(Status status)
        : std::runtime_error(CertificateManager::statusToString(status)) {}

    // Constructor
    CertificateManager::CertificateManager(const std::string& clientId)
        : clientId_(clientId.empty() ? generateClientId() : clientId)
        , initialized_(false)
        , connected_(false) {
        
        // Initialize the C structure to zero
        std::memset(&manager_, 0, sizeof(manager_));
        
        // Set default configuration
        config_.brokerHost = "127.0.0.1";
        config_.brokerPort = 1855;
        config_.useSSL = true;
        config_.caCertFile = "../../ur-rpc-mastered/pkg_src/certs/broker/ca.crt";
        config_.clientCertFile = "../../ur-rpc-mastered/pkg_src/certs/generator-client/client.crt";
        config_.clientKeyFile = "../../ur-rpc-mastered/pkg_src/certs/generator-client/client.key";
    }

    // Destructor
    CertificateManager::~CertificateManager() {
        cleanup();
    }

    // Move constructor
    CertificateManager::CertificateManager(CertificateManager&& other) noexcept
        : manager_(other.manager_)
        , clientId_(std::move(other.clientId_))
        , config_(std::move(other.config_))
        , initialized_(other.initialized_)
        , connected_(other.connected_)
        , responseCallback_(std::move(other.responseCallback_))
        , connectionCallback_(std::move(other.connectionCallback_)) {
        
        // Reset the moved-from object
        std::memset(&other.manager_, 0, sizeof(other.manager_));
        other.initialized_ = false;
        other.connected_ = false;
    }

    // Move assignment operator
    CertificateManager& CertificateManager::operator=(CertificateManager&& other) noexcept {
        if (this != &other) {
            cleanup();
            
            manager_ = other.manager_;
            clientId_ = std::move(other.clientId_);
            config_ = std::move(other.config_);
            initialized_ = other.initialized_;
            connected_ = other.connected_;
            responseCallback_ = std::move(other.responseCallback_);
            connectionCallback_ = std::move(other.connectionCallback_);
            
            // Reset the moved-from object
            std::memset(&other.manager_, 0, sizeof(other.manager_));
            other.initialized_ = false;
            other.connected_ = false;
        }
        return *this;
    }

    // Set connection configuration
    void CertificateManager::setConnectionConfig(const ConnectionConfig& config) {
        if (connected_) {
            throw CertificateException("Cannot change configuration while connected");
        }
        config_ = config;
    }

    // Initialize the certificate manager
    void CertificateManager::initialize() {
        if (initialized_) {
            return; // Already initialized
        }

        // Initialize the C certificate manager (mosquitto_lib_init is called internally)
        cert_status_t status = cert_manager_init(&manager_, clientId_.c_str(),
                                               config_.brokerHost.c_str(),
                                               config_.brokerPort,
                                               config_.useSSL);

        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(static_cast<Status>(status));
        }

        // Set CA certificate file
        std::strncpy(manager_.ca_cert_file, config_.caCertFile.c_str(),
                    sizeof(manager_.ca_cert_file) - 1);

        initialized_ = true;
        std::cout << "✓ Certificate manager initialized successfully" << std::endl;
    }

    // Connect to the broker
    void CertificateManager::connect() {
        if (!initialized_) {
            initialize();
        }

        if (connected_) {
            return; // Already connected
        }

        std::cout << "🔗 Connecting to SSL/TLS broker at " 
                  << config_.brokerHost << ":" << config_.brokerPort << "..." << std::endl;

        cert_status_t status = cert_connect_with_ssl(&manager_,
                                                    config_.clientCertFile.c_str(),
                                                    config_.clientKeyFile.c_str());

        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(static_cast<Status>(status));
        }

        connected_ = true;
        std::cout << "✅ Connected to SSL/TLS broker successfully" << std::endl;
    }

    // Disconnect from the broker
    void CertificateManager::disconnect() {
        if (connected_) {
            cert_manager_disconnect(&manager_);
            connected_ = false;
            std::cout << "📡 Disconnected from broker" << std::endl;
        }
    }

    // Request generic certificate
    Status CertificateManager::requestGenericCertificate(const RequestParams& params) {
        if (!connected_) {
            connect();
        }

        cert_request_params_t c_params = convertRequestParams(params);
        cert_status_t status = cert_request_generic(&manager_, &c_params);
        
        return static_cast<Status>(status);
    }

    // Request client-specific certificate
    Status CertificateManager::requestClientSpecificCertificate(const RequestParams& params) {
        if (!connected_) {
            connect();
        }

        cert_request_params_t c_params = convertRequestParams(params);
        cert_status_t status = cert_request_client_specific(&manager_, &c_params);
        
        return static_cast<Status>(status);
    }

    // Wait for response
    Status CertificateManager::waitForResponse(int timeoutSeconds) {
        cert_status_t status = cert_wait_for_response(&manager_, timeoutSeconds);
        return static_cast<Status>(status);
    }

    // Check existing files
    FileInfo CertificateManager::checkExistingFiles(const std::string& clientId, CertificateType certType) {
        cert_file_info_t c_fileInfo;
        std::string typeStr = certificateTypeToString(certType);
        
        cert_check_existing_files(clientId.c_str(), typeStr.c_str(), &c_fileInfo);
        
        return convertFileInfo(c_fileInfo);
    }

    // Create directory structure
    Status CertificateManager::createDirectoryStructure() {
        cert_status_t status = cert_create_directory_structure();
        return static_cast<Status>(status);
    }

    // Generate filename
    std::string CertificateManager::generateFilename(const std::string& clientId, 
                                                    CertificateType certType, 
                                                    const std::string& extension) {
        std::string typeStr = certificateTypeToString(certType);
        char* filename = cert_generate_filename(clientId.c_str(), typeStr.c_str(), extension.c_str());
        
        std::string result;
        if (filename) {
            result = filename;
            free(filename);
        }
        
        return result;
    }

    // Test SSL connection
    Status CertificateManager::testSSLConnection(const std::string& certPath, const std::string& keyPath) {
        std::cout << "\n🔐 Testing SSL connection with generated certificate..." << std::endl;
        std::cout << "   Certificate: " << certPath << std::endl;
        std::cout << "   Key: " << keyPath << std::endl;

        // Create a test mosquitto client
        struct mosquitto* testMosq = mosquitto_new("ssl_test_client_cpp", true, nullptr);
        if (!testMosq) {
            std::cout << "❌ Failed to create test MQTT client" << std::endl;
            return Status::Error;
        }

        // Setup SSL connection
        cert_status_t sslStatus = cert_setup_ssl_connection(testMosq, certPath.c_str(),
                                                           keyPath.c_str(), config_.caCertFile.c_str());

        if (sslStatus != CERT_STATUS_SUCCESS) {
            std::cout << "❌ Failed to setup SSL connection: " << statusToString(static_cast<Status>(sslStatus)) << std::endl;
            mosquitto_destroy(testMosq);
            return static_cast<Status>(sslStatus);
        }

        std::cout << "✅ SSL connection setup completed successfully" << std::endl;

        // Clean up
        mosquitto_destroy(testMosq);
        return Status::Success;
    }

    // Set response callback
    void CertificateManager::setResponseCallback(ResponseCallback callback) {
        responseCallback_ = callback;
    }

    // Set connection callback
    void CertificateManager::setConnectionCallback(ConnectionCallback callback) {
        connectionCallback_ = callback;
    }

    // Convert status to string
    std::string CertificateManager::statusToString(Status status) {
        const char* c_str = cert_status_to_string(static_cast<cert_status_t>(status));
        return c_str ? c_str : "Unknown status";
    }

    // Convert certificate type to string
    std::string CertificateManager::certificateTypeToString(CertificateType type) {
        switch (type) {
            case CertificateType::Generic:
                return CERT_TYPE_GENERIC;
            case CertificateType::ClientSpecific:
                return CERT_TYPE_CLIENT_SPECIFIC;
            default:
                return "unknown";
        }
    }

    // Convert string to certificate type
    CertificateType CertificateManager::stringToCertificateType(const std::string& typeStr) {
        if (typeStr == CERT_TYPE_GENERIC) {
            return CertificateType::Generic;
        } else if (typeStr == CERT_TYPE_CLIENT_SPECIFIC) {
            return CertificateType::ClientSpecific;
        } else {
            throw CertificateException("Invalid certificate type: " + typeStr);
        }
    }

    // Get last response
    const ResponseData& CertificateManager::getLastResponse() const {
        static ResponseData responseData;
        responseData = convertResponseData(manager_.last_response);
        return responseData;
    }

    // Generate unique client ID
    std::string CertificateManager::generateClientId(const std::string& prefix) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        
        std::ostringstream oss;
        oss << prefix << "_" << dis(gen) << "_" << time_t;
        return oss.str();
    }

    // Check if file is readable
    bool CertificateManager::isFileReadable(const std::string& filepath) {
        return cert_is_file_readable(filepath.c_str());
    }

    // Get file creation time
    std::chrono::system_clock::time_point CertificateManager::getFileCreationTime(const std::string& filepath) {
        time_t c_time = cert_get_file_creation_time(filepath.c_str());
        return std::chrono::system_clock::from_time_t(c_time);
    }

    // Convert request parameters to C structure
    cert_request_params_t CertificateManager::convertRequestParams(const RequestParams& params) {
        cert_request_params_t c_params;
        std::memset(&c_params, 0, sizeof(c_params));
        
        std::strncpy(c_params.client_id, params.clientId.c_str(), sizeof(c_params.client_id) - 1);
        std::strncpy(c_params.cert_type, certificateTypeToString(params.certType).c_str(), sizeof(c_params.cert_type) - 1);
        std::strncpy(c_params.common_name, params.commonName.c_str(), sizeof(c_params.common_name) - 1);
        std::strncpy(c_params.organization, params.organization.c_str(), sizeof(c_params.organization) - 1);
        std::strncpy(c_params.country, params.country.c_str(), sizeof(c_params.country) - 1);
        c_params.validity_days = params.validityDays;
        c_params.timestamp = std::chrono::system_clock::to_time_t(params.timestamp);
        
        return c_params;
    }

    // Convert response data from C structure
    ResponseData CertificateManager::convertResponseData(const cert_response_data_t& response) const {
        ResponseData data;
        data.status = static_cast<Status>(response.status);
        data.errorMessage = response.error_message;
        data.certificateData = response.certificate_data;
        data.privateKeyData = response.private_key_data;
        data.certFilename = response.cert_filename;
        data.keyFilename = response.key_filename;
        return data;
    }

    // Convert file info from C structure
    FileInfo CertificateManager::convertFileInfo(const cert_file_info_t& fileInfo) {
        FileInfo info;
        info.certPath = fileInfo.cert_path;
        info.keyPath = fileInfo.key_path;
        info.creationTime = std::chrono::system_clock::from_time_t(fileInfo.creation_time);
        info.exists = fileInfo.exists;
        info.valid = fileInfo.valid;
        return info;
    }

    // Cleanup resources
    void CertificateManager::cleanup() {
        if (connected_) {
            disconnect();
        }
        
        if (initialized_) {
            cert_manager_cleanup(&manager_);
            // Note: mosquitto_lib_cleanup() is already called in cert_manager_cleanup()
            initialized_ = false;
        }
    }

    // Batch Certificate Manager Implementation
    BatchCertificateManager::BatchCertificateManager(CertificateManager& manager)
        : manager_(manager) {}

    BatchCertificateManager::BatchResult BatchCertificateManager::executeRequests(const BatchRequest& requests) {
        BatchResult results;
        results.reserve(requests.size());

        for (const auto& request : requests) {
            Status status = executeRequest(request);
            results.emplace_back(request, status);
        }

        return results;
    }

    Status BatchCertificateManager::executeRequest(const RequestParams& params) {
        try {
            Status status;
            if (params.certType == CertificateType::Generic) {
                status = manager_.requestGenericCertificate(params);
            } else {
                status = manager_.requestClientSpecificCertificate(params);
            }

            if (status == Status::Success) {
                status = manager_.waitForResponse(30);
            }

            return status;
        } catch (const CertificateException&) {
            return Status::Error;
        }
    }

    // Utility functions
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d_%H-%M-%S");
        return oss.str();
    }

    bool createDirectory(const std::string& path) {
        return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
    }

    std::vector<std::string> listCertificateFiles(const std::string& /* directory */) {
        std::vector<std::string> files;
        // Implementation would use readdir or filesystem library
        // For now, return empty vector
        return files;
    }

    // Configuration management implementation
    AppConfig CertificateManager::loadConfigFromFile(const std::string& configPath) {
        AppConfig config; // Start with defaults
        
        // Read the JSON file
        FILE* file = fopen(configPath.c_str(), "r");
        if (!file) {
            std::cout << "⚠️  Warning: Could not open config file '" << configPath 
                      << "', using defaults" << std::endl;
            return config;
        }
        
        // Get file size
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        // Read file content
        std::string jsonContent(fileSize, '\0');
        fread(&jsonContent[0], 1, fileSize, file);
        fclose(file);
        
        // Parse JSON
        cJSON* json = cJSON_Parse(jsonContent.c_str());
        if (!json) {
            std::cout << "⚠️  Warning: Invalid JSON in config file '" << configPath 
                      << "', using defaults" << std::endl;
            return config;
        }
        
        // Parse broker configuration
        cJSON* broker = cJSON_GetObjectItem(json, "broker");
        if (broker) {
            cJSON* host = cJSON_GetObjectItem(broker, "host");
            if (cJSON_IsString(host)) {
                config.brokerHost = host->valuestring;
            }
            
            cJSON* port = cJSON_GetObjectItem(broker, "port");
            if (cJSON_IsNumber(port)) {
                config.brokerPort = port->valueint;
            }
            
            cJSON* ssl = cJSON_GetObjectItem(broker, "ssl");
            if (cJSON_IsBool(ssl)) {
                config.useSSL = cJSON_IsTrue(ssl);
            }
        }
        
        // Parse certificate paths
        cJSON* certs = cJSON_GetObjectItem(json, "certificates");
        if (certs) {
            cJSON* caCert = cJSON_GetObjectItem(certs, "ca_cert");
            if (cJSON_IsString(caCert)) {
                config.caCertFile = caCert->valuestring;
            }
            
            cJSON* clientCert = cJSON_GetObjectItem(certs, "client_cert");
            if (cJSON_IsString(clientCert)) {
                config.clientCertFile = clientCert->valuestring;
            }
            
            cJSON* clientKey = cJSON_GetObjectItem(certs, "client_key");
            if (cJSON_IsString(clientKey)) {
                config.clientKeyFile = clientKey->valuestring;
            }
            
            cJSON* outputDir = cJSON_GetObjectItem(certs, "output_directory");
            if (cJSON_IsString(outputDir)) {
                config.certOutputDirectory = outputDir->valuestring;
            }
        }
        
        // Parse defaults
        cJSON* defaults = cJSON_GetObjectItem(json, "defaults");
        if (defaults) {
            cJSON* clientId = cJSON_GetObjectItem(defaults, "client_id");
            if (cJSON_IsString(clientId)) {
                config.defaultClientId = clientId->valuestring;
            }
            
            cJSON* org = cJSON_GetObjectItem(defaults, "organization");
            if (cJSON_IsString(org)) {
                config.defaultOrganization = org->valuestring;
            }
            
            cJSON* cn = cJSON_GetObjectItem(defaults, "common_name");
            if (cJSON_IsString(cn)) {
                config.defaultCommonName = cn->valuestring;
            }
            
            cJSON* validity = cJSON_GetObjectItem(defaults, "validity_days");
            if (cJSON_IsNumber(validity)) {
                config.defaultValidityDays = validity->valueint;
            }
        }
        
        // Parse options
        cJSON* options = cJSON_GetObjectItem(json, "options");
        if (options) {
            cJSON* verbose = cJSON_GetObjectItem(options, "verbose");
            if (cJSON_IsBool(verbose)) {
                config.enableVerbose = cJSON_IsTrue(verbose);
            }
            
            cJSON* testing = cJSON_GetObjectItem(options, "enable_testing");
            if (cJSON_IsBool(testing)) {
                config.enableTesting = cJSON_IsTrue(testing);
            }
        }
        
        cJSON_Delete(json);
        return config;
    }

    bool CertificateManager::saveConfigToFile(const AppConfig& config, const std::string& configPath) {
        cJSON* json = cJSON_CreateObject();
        
        // Broker configuration
        cJSON* broker = cJSON_CreateObject();
        cJSON_AddStringToObject(broker, "host", config.brokerHost.c_str());
        cJSON_AddNumberToObject(broker, "port", config.brokerPort);
        cJSON_AddBoolToObject(broker, "ssl", config.useSSL);
        cJSON_AddItemToObject(json, "broker", broker);
        
        // Certificate paths
        cJSON* certs = cJSON_CreateObject();
        cJSON_AddStringToObject(certs, "ca_cert", config.caCertFile.c_str());
        cJSON_AddStringToObject(certs, "client_cert", config.clientCertFile.c_str());
        cJSON_AddStringToObject(certs, "client_key", config.clientKeyFile.c_str());
        cJSON_AddStringToObject(certs, "output_directory", config.certOutputDirectory.c_str());
        cJSON_AddItemToObject(json, "certificates", certs);
        
        // Defaults
        cJSON* defaults = cJSON_CreateObject();
        cJSON_AddStringToObject(defaults, "client_id", config.defaultClientId.c_str());
        cJSON_AddStringToObject(defaults, "organization", config.defaultOrganization.c_str());
        cJSON_AddStringToObject(defaults, "common_name", config.defaultCommonName.c_str());
        cJSON_AddNumberToObject(defaults, "validity_days", config.defaultValidityDays);
        cJSON_AddItemToObject(json, "defaults", defaults);
        
        // Options
        cJSON* options = cJSON_CreateObject();
        cJSON_AddBoolToObject(options, "verbose", config.enableVerbose);
        cJSON_AddBoolToObject(options, "enable_testing", config.enableTesting);
        cJSON_AddItemToObject(json, "options", options);
        
        // Convert to string and write to file
        char* jsonString = cJSON_Print(json);
        if (!jsonString) {
            cJSON_Delete(json);
            return false;
        }
        
        FILE* file = fopen(configPath.c_str(), "w");
        if (!file) {
            free(jsonString);
            cJSON_Delete(json);
            return false;
        }
        
        fprintf(file, "%s", jsonString);
        fclose(file);
        
        free(jsonString);
        cJSON_Delete(json);
        return true;
    }

    void CertificateManager::printConfiguration(const AppConfig& config) {
        std::cout << "📋 Configuration Settings:\n"
                  << "   Broker: " << config.brokerHost << ":" << config.brokerPort
                  << (config.useSSL ? " (SSL)" : " (TCP)") << "\n"
                  << "   CA Certificate: " << config.caCertFile << "\n"
                  << "   Client Certificate: " << config.clientCertFile << "\n"
                  << "   Client Key: " << config.clientKeyFile << "\n"
                  << "   Output Directory: " << config.certOutputDirectory << "\n"
                  << "   Default Client ID: " << config.defaultClientId << "\n"
                  << "   Default Organization: " << config.defaultOrganization << "\n"
                  << "   Default Common Name: " << config.defaultCommonName << "\n"
                  << "   Default Validity: " << config.defaultValidityDays << " days\n"
                  << "   Verbose: " << (config.enableVerbose ? "enabled" : "disabled") << "\n"
                  << "   Testing: " << (config.enableTesting ? "enabled" : "disabled") << std::endl;
    }

    AppConfig CertificateManager::mergeConfigWithCliArgs(const AppConfig& config, int argc, char* argv[]) {
        AppConfig result = config; // Start with config file values
        
        // CLI argument parsing
        static struct option long_options[] = {
            {"help", no_argument, 0, 'h'},
            {"verbose", no_argument, 0, 'v'},
            {"client-id", required_argument, 0, 'c'},
            {"org", required_argument, 0, 'o'},
            {"cn", required_argument, 0, 'n'},
            {"days", required_argument, 0, 'd'},
            {"no-test", no_argument, 0, 't'},
            {"host", required_argument, 0, 'H'},
            {"port", required_argument, 0, 'P'},
            {"ca-cert", required_argument, 0, 'C'},
            {"client-cert", required_argument, 0, 'e'},
            {"client-key", required_argument, 0, 'k'},
            {"output-dir", required_argument, 0, 'O'},
            {"config", required_argument, 0, 'f'},
            {0, 0, 0, 0}
        };
        
        int option_index = 0;
        int c;
        
        while ((c = getopt_long(argc, argv, "hvc:o:n:d:tH:P:C:e:k:O:f:", long_options, &option_index)) != -1) {
            switch (c) {
                case 'c':
                    result.defaultClientId = optarg;
                    break;
                case 'o':
                    result.defaultOrganization = optarg;
                    break;
                case 'n':
                    result.defaultCommonName = optarg;
                    break;
                case 'd':
                    result.defaultValidityDays = std::atoi(optarg);
                    break;
                case 'v':
                    result.enableVerbose = true;
                    break;
                case 't':
                    result.enableTesting = false;
                    break;
                case 'H':
                    result.brokerHost = optarg;
                    break;
                case 'P':
                    result.brokerPort = std::atoi(optarg);
                    break;
                case 'C':
                    result.caCertFile = optarg;
                    break;
                case 'e':
                    result.clientCertFile = optarg;
                    break;
                case 'k':
                    result.clientKeyFile = optarg;
                    break;
                case 'O':
                    result.certOutputDirectory = optarg;
                    break;
                default:
                    break;
            }
        }
        
        return result;
    }

} // namespace CertificateAPI
