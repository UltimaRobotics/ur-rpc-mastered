#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <map>
#include <iostream>
#include <stdexcept>

extern "C" {
    #include "cert_manager.h"
}

namespace CertificateAPI {

    // C++ wrapper for certificate status
    enum class Status {
        Success = CERT_STATUS_SUCCESS,
        Error = CERT_STATUS_ERROR,
        Timeout = CERT_STATUS_TIMEOUT,
        InvalidResponse = CERT_STATUS_INVALID_RESPONSE,
        FileError = CERT_STATUS_FILE_ERROR,
        AlreadyExists = CERT_STATUS_ALREADY_EXISTS
    };

    // Certificate types
    enum class CertificateType {
        Generic,
        ClientSpecific
    };

    // File information wrapper
    struct FileInfo {
        std::string certPath;
        std::string keyPath;
        std::chrono::system_clock::time_point creationTime;
        bool exists;
        bool valid;

        FileInfo() : exists(false), valid(false) {}
    };

    // Certificate request parameters
    struct RequestParams {
        std::string clientId;
        CertificateType certType;
        std::string commonName;
        std::string organization;
        std::string country;
        int validityDays;
        std::chrono::system_clock::time_point timestamp;

        RequestParams() : certType(CertificateType::Generic), country("US"), validityDays(365) {
            timestamp = std::chrono::system_clock::now();
        }
    };

    // Certificate response data
    struct ResponseData {
        Status status;
        std::string errorMessage;
        std::string certificateData;
        std::string privateKeyData;
        std::string certFilename;
        std::string keyFilename;

        ResponseData() : status(Status::Error) {}
    };

    // Application configuration structure
    struct AppConfig {
        std::string brokerHost;
        int brokerPort;
        bool useSSL;
        std::string caCertFile;
        std::string clientCertFile;
        std::string clientKeyFile;
        std::string certOutputDirectory;
        std::string defaultClientId;
        std::string defaultOrganization;
        std::string defaultCommonName;
        int defaultValidityDays;
        bool enableVerbose;
        bool enableTesting;
        
        // Default constructor with sensible defaults
        AppConfig() :
            brokerHost("127.0.0.1"),
            brokerPort(1855),
            useSSL(true),
            caCertFile("../../ur-rpc-mastered/pkg_src/certs/broker/ca.crt"),
            clientCertFile("../../ur-rpc-mastered/pkg_src/certs/generator-client/client.crt"),
            clientKeyFile("../../ur-rpc-mastered/pkg_src/certs/generator-client/client.key"),
            certOutputDirectory("certs/generated"),
            defaultClientId("cpp_client"),
            defaultOrganization("TestOrgCPP"),
            defaultCommonName("mqtt-client-cpp"),
            defaultValidityDays(365),
            enableVerbose(false),
            enableTesting(true) {}
    };

    // Connection configuration (maintained for backward compatibility)
    struct ConnectionConfig {
        std::string brokerHost;
        int brokerPort;
        bool useSSL;
        std::string caCertFile;
        std::string clientCertFile;
        std::string clientKeyFile;
        
        ConnectionConfig() : brokerHost("127.0.0.1"), brokerPort(1855), useSSL(true) {}
    };

    // Forward declaration
    class CertificateManager;

    // Exception class for certificate operations
    class CertificateException : public std::runtime_error {
    public:
        explicit CertificateException(const std::string& message) 
            : std::runtime_error(message) {}
        
        explicit CertificateException(Status status);
    };

    // Main Certificate Manager class
    class CertificateManager {
    public:
        // Callback function types
        using ResponseCallback = std::function<void(const ResponseData&)>;
        using ConnectionCallback = std::function<void(bool connected)>;

    private:
        cert_manager_t manager_;
        std::string clientId_;
        ConnectionConfig config_;
        bool initialized_;
        bool connected_;
        ResponseCallback responseCallback_;
        ConnectionCallback connectionCallback_;

    public:
        // Constructor
        explicit CertificateManager(const std::string& clientId = "");
        
        // Destructor
        ~CertificateManager();

        // Copy constructor (deleted)
        CertificateManager(const CertificateManager&) = delete;
        
        // Assignment operator (deleted)
        CertificateManager& operator=(const CertificateManager&) = delete;

        // Move constructor
        CertificateManager(CertificateManager&& other) noexcept;
        
        // Move assignment operator
        CertificateManager& operator=(CertificateManager&& other) noexcept;

        // Configuration
        void setConnectionConfig(const ConnectionConfig& config);
        const ConnectionConfig& getConnectionConfig() const { return config_; }

        // Connection management
        void initialize();
        void connect();
        void disconnect();
        bool isConnected() const { return connected_; }

        // Certificate operations
        Status requestGenericCertificate(const RequestParams& params);
        Status requestClientSpecificCertificate(const RequestParams& params);
        Status waitForResponse(int timeoutSeconds = 30);
        
        // File management
        FileInfo checkExistingFiles(const std::string& clientId, CertificateType certType);
        Status createDirectoryStructure();
        std::string generateFilename(const std::string& clientId, CertificateType certType, const std::string& extension);
        
        // SSL connection testing
        Status testSSLConnection(const std::string& certPath, const std::string& keyPath);
        
        // Callback management
        void setResponseCallback(ResponseCallback callback);
        void setConnectionCallback(ConnectionCallback callback);
        
        // Utility functions
        static std::string statusToString(Status status);
        static std::string certificateTypeToString(CertificateType type);
        static CertificateType stringToCertificateType(const std::string& typeStr);
        
        // Get last response
        const ResponseData& getLastResponse() const;
        
        // Generate unique client ID
        static std::string generateClientId(const std::string& prefix = "cpp_client");
        
        // Certificate validation
        static bool isFileReadable(const std::string& filepath);
        static std::chrono::system_clock::time_point getFileCreationTime(const std::string& filepath);

        // Configuration management
        static AppConfig loadConfigFromFile(const std::string& configPath);
        static bool saveConfigToFile(const AppConfig& config, const std::string& configPath);
        static AppConfig mergeConfigWithCliArgs(const AppConfig& config, int argc, char* argv[]);
        static void printConfiguration(const AppConfig& config);

    private:
        // Internal conversion functions
        cert_request_params_t convertRequestParams(const RequestParams& params);
        RequestParams convertRequestParams(const cert_request_params_t& params);
        ResponseData convertResponseData(const cert_response_data_t& response) const;
        FileInfo convertFileInfo(const cert_file_info_t& fileInfo);
        
        // Internal initialization
        void cleanup();
        void setupCallbacks();
    };

    // Batch operations helper
    class BatchCertificateManager {
    public:
        using BatchRequest = std::vector<RequestParams>;
        using BatchResult = std::vector<std::pair<RequestParams, Status>>;

    private:
        CertificateManager& manager_;
        
    public:
        explicit BatchCertificateManager(CertificateManager& manager);
        
        BatchResult executeRequests(const BatchRequest& requests);
        Status executeRequest(const RequestParams& params);
    };

    // Utility functions
    std::string getCurrentTimestamp();
    bool createDirectory(const std::string& path);
    std::vector<std::string> listCertificateFiles(const std::string& directory);

} // namespace CertificateAPI

#endif // CERTIFICATE_MANAGER_HPP
