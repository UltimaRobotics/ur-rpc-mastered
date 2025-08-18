/*
 * C++ Certificate Client Wrapper - Header File
 * Modern C++ wrapper for the Certificate Manager API
 * Provides object-oriented interface for MQTT certificate generation
 */

#ifndef CERTIFICATE_CLIENT_HPP
#define CERTIFICATE_CLIENT_HPP

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <map>
#include <stdexcept>

// Forward declarations for C types
extern "C" {
    #include "cert_manager.h"
}

namespace CertificateAPI {

    // C++ Status enum wrapper
    enum class Status {
        Success = CERT_STATUS_SUCCESS,
        Error = CERT_STATUS_ERROR,
        Timeout = CERT_STATUS_TIMEOUT,
        InvalidResponse = CERT_STATUS_INVALID_RESPONSE,
        FileError = CERT_STATUS_FILE_ERROR,
        AlreadyExists = CERT_STATUS_ALREADY_EXISTS
    };

    // C++ Certificate File Info wrapper
    class CertificateFileInfo {
    public:
        std::string certPath;
        std::string keyPath;
        std::chrono::system_clock::time_point creationTime;
        bool exists;
        bool valid;

        CertificateFileInfo() : exists(false), valid(false) {}
        
        // Convert from C struct
        static CertificateFileInfo fromC(const cert_file_info_t& cInfo);
        
        // Convert to C struct
        cert_file_info_t toC() const;
    };

    // C++ Certificate Request Parameters wrapper
    class CertificateRequestParams {
    public:
        std::string clientId;
        std::string certType;
        std::string commonName;
        std::string organization;
        std::string country;
        int validityDays;
        std::chrono::system_clock::time_point timestamp;

        CertificateRequestParams(const std::string& clientId, 
                               const std::string& certType = "generic",
                               const std::string& commonName = "MQTT Client",
                               const std::string& organization = "MQTT Broker System",
                               const std::string& country = "US",
                               int validityDays = 365);

        // Convert to C struct
        cert_request_params_t toC() const;
    };

    // C++ Certificate Response Data wrapper
    class CertificateResponseData {
    public:
        Status status;
        std::string errorMessage;
        std::string certificateData;
        std::string privateKeyData;
        std::string certFilename;
        std::string keyFilename;

        CertificateResponseData() : status(Status::Error) {}

        // Convert from C struct
        static CertificateResponseData fromC(const cert_response_data_t& cResponse);
    };

    // Callback function types
    using ResponseCallback = std::function<void(const CertificateResponseData&)>;
    using ConnectionCallback = std::function<void(bool connected)>;

    // Exception classes
    class CertificateException : public std::runtime_error {
    public:
        explicit CertificateException(const std::string& message) 
            : std::runtime_error(message) {}
        explicit CertificateException(Status status);
    };

    // Main Certificate Client class
    class CertificateClient {
    private:
        std::unique_ptr<cert_manager_t> manager_;
        std::string clientId_;
        std::string brokerHost_;
        int brokerPort_;
        bool useSSL_;
        std::string caCertFile_;
        ResponseCallback responseCallback_;
        ConnectionCallback connectionCallback_;
        
    public:
        // Constructor
        CertificateClient(const std::string& clientId,
                         const std::string& brokerHost = "127.0.0.1",
                         int brokerPort = 1856,
                         bool useSSL = false);

        // Destructor
        ~CertificateClient();

        // Copy constructor and assignment operator (deleted)
        CertificateClient(const CertificateClient&) = delete;
        CertificateClient& operator=(const CertificateClient&) = delete;

        // Move constructor and assignment operator
        CertificateClient(CertificateClient&& other) noexcept;
        CertificateClient& operator=(CertificateClient&& other) noexcept;

        // Configuration methods
        void setSSLMode(bool useSSL) { useSSL_ = useSSL; }
        void setCACertificateFile(const std::string& caCertFile) { caCertFile_ = caCertFile; }
        void setBrokerPort(int port) { brokerPort_ = port; }
        void setResponseCallback(ResponseCallback callback) { responseCallback_ = std::move(callback); }
        void setConnectionCallback(ConnectionCallback callback) { connectionCallback_ = std::move(callback); }

        // Connection management
        void connect();
        void disconnect();
        bool isConnected() const;

        // Certificate operations
        CertificateResponseData requestGenericCertificate(const CertificateRequestParams& params);
        CertificateResponseData requestClientSpecificCertificate(const CertificateRequestParams& params);
        CertificateResponseData requestCertificate(const CertificateRequestParams& params);
        
        // Utility methods
        CertificateFileInfo checkExistingCertificates(const std::string& certType) const;
        bool validateFilePermissions(const std::string& certPath, const std::string& keyPath) const;
        std::string getStatusString(Status status) const;
        
        // SSL connection setup
        void setupSSLConnection(const std::string& certPath, const std::string& keyPath);
        void connectWithSSL(const std::string& certPath, const std::string& keyPath);

        // Advanced features
        int checkCertificateExpiration(const std::string& certPath) const;
        void autoRenewIfNeeded(const CertificateRequestParams& params, int renewalThresholdDays = 30);

        // Getters
        const std::string& getClientId() const { return clientId_; }
        const std::string& getBrokerHost() const { return brokerHost_; }
        int getBrokerPort() const { return brokerPort_; }
        bool isSSLEnabled() const { return useSSL_; }
        
        // Friend class declaration
        friend class BatchRequestManager;
    };

    // Batch Request Manager
    class BatchRequestManager {
    private:
        std::unique_ptr<cert_batch_request_t> batch_;
        std::vector<CertificateRequestParams> requests_;
        std::vector<Status> results_;
        
    public:
        BatchRequestManager(int requestCount);
        ~BatchRequestManager();

        // Batch operations
        void addRequest(const CertificateRequestParams& params);
        void executeAll(CertificateClient& client);
        std::vector<Status> getResults() const { return results_; }
        int getCompletedCount() const;
        bool isCompleted() const;
        
        // Clear and reset
        void clear();
    };

    // Factory methods
    std::unique_ptr<CertificateClient> createSSLClient(
        const std::string& clientId,
        const std::string& brokerHost = "127.0.0.1",
        int sslPort = 1855,
        const std::string& caCertFile = "ca.crt");

    std::unique_ptr<CertificateClient> createTCPClient(
        const std::string& clientId,
        const std::string& brokerHost = "127.0.0.1",
        int tcpPort = 1856);

    // Utility functions
    std::string generateClientId(const std::string& prefix = "cert_client");
    std::vector<std::string> listGeneratedCertificates();
    void createDirectoryStructure();
    
    // Status conversion utilities
    Status convertCStatus(cert_status_t cStatus);
    cert_status_t convertCppStatus(Status cppStatus);
    
} // namespace CertificateAPI

#endif // CERTIFICATE_CLIENT_HPP