/*
 * C++ Certificate Client Wrapper - Implementation File
 * Modern C++ wrapper for the Certificate Manager API
 * Provides object-oriented interface for MQTT certificate generation
 */

#include "CertificateClient.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <filesystem>
#include <algorithm>

extern "C" {
    #include "cert_manager.h"
}

namespace CertificateAPI {

    // CertificateFileInfo Implementation
    CertificateFileInfo CertificateFileInfo::fromC(const cert_file_info_t& cInfo) {
        CertificateFileInfo info;
        info.certPath = std::string(cInfo.cert_path);
        info.keyPath = std::string(cInfo.key_path);
        info.creationTime = std::chrono::system_clock::from_time_t(cInfo.creation_time);
        info.exists = cInfo.exists;
        info.valid = cInfo.valid;
        return info;
    }

    cert_file_info_t CertificateFileInfo::toC() const {
        cert_file_info_t cInfo;
        memset(&cInfo, 0, sizeof(cInfo));
        strncpy(cInfo.cert_path, certPath.c_str(), sizeof(cInfo.cert_path) - 1);
        strncpy(cInfo.key_path, keyPath.c_str(), sizeof(cInfo.key_path) - 1);
        cInfo.creation_time = std::chrono::system_clock::to_time_t(creationTime);
        cInfo.exists = exists;
        cInfo.valid = valid;
        return cInfo;
    }

    // CertificateRequestParams Implementation
    CertificateRequestParams::CertificateRequestParams(const std::string& clientId, 
                                                     const std::string& certType,
                                                     const std::string& commonName,
                                                     const std::string& organization,
                                                     const std::string& country,
                                                     int validityDays)
        : clientId(clientId), certType(certType), commonName(commonName),
          organization(organization), country(country), validityDays(validityDays),
          timestamp(std::chrono::system_clock::now()) {
    }

    cert_request_params_t CertificateRequestParams::toC() const {
        cert_request_params_t cParams;
        memset(&cParams, 0, sizeof(cParams));
        strncpy(cParams.client_id, clientId.c_str(), sizeof(cParams.client_id) - 1);
        strncpy(cParams.cert_type, certType.c_str(), sizeof(cParams.cert_type) - 1);
        strncpy(cParams.common_name, commonName.c_str(), sizeof(cParams.common_name) - 1);
        strncpy(cParams.organization, organization.c_str(), sizeof(cParams.organization) - 1);
        strncpy(cParams.country, country.c_str(), sizeof(cParams.country) - 1);
        cParams.validity_days = validityDays;
        cParams.timestamp = std::chrono::system_clock::to_time_t(timestamp);
        return cParams;
    }

    // CertificateResponseData Implementation
    CertificateResponseData CertificateResponseData::fromC(const cert_response_data_t& cResponse) {
        CertificateResponseData response;
        response.status = convertCStatus(cResponse.status);
        response.errorMessage = std::string(cResponse.error_message);
        response.certificateData = std::string(cResponse.certificate_data);
        response.privateKeyData = std::string(cResponse.private_key_data);
        response.certFilename = std::string(cResponse.cert_filename);
        response.keyFilename = std::string(cResponse.key_filename);
        return response;
    }

    // CertificateException Implementation
    CertificateException::CertificateException(Status status) 
        : std::runtime_error("Certificate operation failed: " + std::to_string(static_cast<int>(status))) {
    }

    // CertificateClient Implementation
    CertificateClient::CertificateClient(const std::string& clientId,
                                       const std::string& brokerHost,
                                       int brokerPort,
                                       bool useSSL)
        : manager_(std::make_unique<cert_manager_t>()),
          clientId_(clientId),
          brokerHost_(brokerHost),
          brokerPort_(brokerPort),
          useSSL_(useSSL),
          caCertFile_("ca.crt") {
        
        memset(manager_.get(), 0, sizeof(cert_manager_t));
        
        // Initialize with default CA certificate if using SSL
        if (useSSL_) {
            caCertFile_ = "ca.crt";
        }
    }

    CertificateClient::~CertificateClient() {
        try {
            disconnect();
        } catch (...) {
            // Ignore exceptions in destructor
        }
    }

    CertificateClient::CertificateClient(CertificateClient&& other) noexcept
        : manager_(std::move(other.manager_)),
          clientId_(std::move(other.clientId_)),
          brokerHost_(std::move(other.brokerHost_)),
          brokerPort_(other.brokerPort_),
          useSSL_(other.useSSL_),
          caCertFile_(std::move(other.caCertFile_)),
          responseCallback_(std::move(other.responseCallback_)),
          connectionCallback_(std::move(other.connectionCallback_)) {
    }

    CertificateClient& CertificateClient::operator=(CertificateClient&& other) noexcept {
        if (this != &other) {
            disconnect();
            manager_ = std::move(other.manager_);
            clientId_ = std::move(other.clientId_);
            brokerHost_ = std::move(other.brokerHost_);
            brokerPort_ = other.brokerPort_;
            useSSL_ = other.useSSL_;
            caCertFile_ = std::move(other.caCertFile_);
            responseCallback_ = std::move(other.responseCallback_);
            connectionCallback_ = std::move(other.connectionCallback_);
        }
        return *this;
    }

    void CertificateClient::connect() {
        cert_status_t status = cert_manager_init(manager_.get(), clientId_.c_str(),
                                               brokerHost_.c_str(), brokerPort_, useSSL_);
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        status = cert_manager_connect(manager_.get());
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        if (connectionCallback_) {
            connectionCallback_(true);
        }
    }

    void CertificateClient::disconnect() {
        if (manager_ && manager_->mosq) {
            cert_manager_disconnect(manager_.get());
            cert_manager_cleanup(manager_.get());
            
            if (connectionCallback_) {
                connectionCallback_(false);
            }
        }
    }

    bool CertificateClient::isConnected() const {
        return manager_ && manager_->connected;
    }

    CertificateResponseData CertificateClient::requestGenericCertificate(const CertificateRequestParams& params) {
        cert_request_params_t cParams = params.toC();
        cert_status_t status = cert_request_generic(manager_.get(), &cParams);
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        status = cert_wait_for_response(manager_.get(), MAX_RESPONSE_WAIT_TIME);
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        CertificateResponseData response = CertificateResponseData::fromC(manager_->last_response);
        
        if (responseCallback_) {
            responseCallback_(response);
        }

        return response;
    }

    CertificateResponseData CertificateClient::requestClientSpecificCertificate(const CertificateRequestParams& params) {
        cert_request_params_t cParams = params.toC();
        cert_status_t status = cert_request_client_specific(manager_.get(), &cParams);
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        status = cert_wait_for_response(manager_.get(), MAX_RESPONSE_WAIT_TIME);
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        CertificateResponseData response = CertificateResponseData::fromC(manager_->last_response);
        
        if (responseCallback_) {
            responseCallback_(response);
        }

        return response;
    }

    CertificateResponseData CertificateClient::requestCertificate(const CertificateRequestParams& params) {
        cert_request_params_t cParams = params.toC();
        cert_status_t status = cert_request_certificate(manager_.get(), &cParams);
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        status = cert_wait_for_response(manager_.get(), MAX_RESPONSE_WAIT_TIME);
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }

        CertificateResponseData response = CertificateResponseData::fromC(manager_->last_response);
        
        if (responseCallback_) {
            responseCallback_(response);
        }

        return response;
    }

    CertificateFileInfo CertificateClient::checkExistingCertificates(const std::string& certType) const {
        cert_file_info_t cInfo;
        cert_status_t status = cert_check_existing_files(clientId_.c_str(), certType.c_str(), &cInfo);
        
        if (status == CERT_STATUS_ALREADY_EXISTS) {
            return CertificateFileInfo::fromC(cInfo);
        }
        
        return CertificateFileInfo(); // Empty info if not found
    }

    bool CertificateClient::validateFilePermissions(const std::string& certPath, const std::string& keyPath) const {
        cert_status_t status = cert_validate_file_permissions(certPath.c_str(), keyPath.c_str());
        return status == CERT_STATUS_SUCCESS;
    }

    std::string CertificateClient::getStatusString(Status status) const {
        return std::string(cert_status_to_string(convertCppStatus(status)));
    }

    void CertificateClient::setupSSLConnection(const std::string& certPath, const std::string& keyPath) {
        if (!manager_->mosq) {
            throw CertificateException(Status::Error);
        }

        cert_status_t status = cert_setup_ssl_connection(manager_->mosq, certPath.c_str(), 
                                                        keyPath.c_str(), caCertFile_.c_str());
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
    }

    void CertificateClient::connectWithSSL(const std::string& certPath, const std::string& keyPath) {
        cert_status_t status = cert_connect_with_ssl(manager_.get(), certPath.c_str(), keyPath.c_str());
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
    }

    int CertificateClient::checkCertificateExpiration(const std::string& certPath) const {
        int daysUntilExpiry = 0;
        cert_status_t status = cert_check_expiration(certPath.c_str(), &daysUntilExpiry);
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
        
        return daysUntilExpiry;
    }

    void CertificateClient::autoRenewIfNeeded(const CertificateRequestParams& params, int renewalThresholdDays) {
        cert_request_params_t cParams = params.toC();
        cert_status_t status = cert_auto_renew_if_needed(manager_.get(), &cParams, renewalThresholdDays);
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
    }

    // BatchRequestManager Implementation
    BatchRequestManager::BatchRequestManager(int requestCount) 
        : batch_(std::make_unique<cert_batch_request_t>()) {
        cert_status_t status = cert_batch_request_init(batch_.get(), requestCount);
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
        requests_.reserve(requestCount);
        results_.reserve(requestCount);
    }

    BatchRequestManager::~BatchRequestManager() {
        if (batch_) {
            cert_batch_cleanup(batch_.get());
        }
    }

    void BatchRequestManager::addRequest(const CertificateRequestParams& params) {
        cert_request_params_t cParams = params.toC();
        cert_status_t status = cert_batch_add_request(batch_.get(), &cParams);
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
        
        requests_.push_back(params);
    }

    void BatchRequestManager::executeAll(CertificateClient& client) {
        cert_status_t status = cert_batch_execute(client.manager_.get(), batch_.get());
        
        if (status != CERT_STATUS_SUCCESS) {
            throw CertificateException(convertCStatus(status));
        }
        
        // Convert results
        results_.clear();
        for (int i = 0; i < batch_->count; ++i) {
            results_.push_back(convertCStatus(batch_->results[i]));
        }
    }

    int BatchRequestManager::getCompletedCount() const {
        return batch_ ? batch_->completed : 0;
    }

    bool BatchRequestManager::isCompleted() const {
        return batch_ && (batch_->completed == batch_->count);
    }

    void BatchRequestManager::clear() {
        requests_.clear();
        results_.clear();
        if (batch_) {
            cert_batch_cleanup(batch_.get());
            cert_batch_request_init(batch_.get(), 0);
        }
    }

    // Factory methods implementation
    std::unique_ptr<CertificateClient> createSSLClient(
        const std::string& clientId,
        const std::string& brokerHost,
        int sslPort,
        const std::string& caCertFile) {
        
        auto client = std::make_unique<CertificateClient>(clientId, brokerHost, sslPort, true);
        client->setCACertificateFile(caCertFile);
        return client;
    }

    std::unique_ptr<CertificateClient> createTCPClient(
        const std::string& clientId,
        const std::string& brokerHost,
        int tcpPort) {
        
        return std::make_unique<CertificateClient>(clientId, brokerHost, tcpPort, false);
    }

    // Utility functions implementation
    std::string generateClientId(const std::string& prefix) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        return prefix + "_" + std::to_string(dis(gen)) + "_" + std::to_string(timestamp);
    }

    std::vector<std::string> listGeneratedCertificates() {
        std::vector<std::string> certificates;
        
        try {
            if (std::filesystem::exists(CERT_DIRECTORY)) {
                for (const auto& entry : std::filesystem::directory_iterator(CERT_DIRECTORY)) {
                    if (entry.is_regular_file() && entry.path().extension() == ".crt") {
                        certificates.push_back(entry.path().filename().string());
                    }
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            // Directory doesn't exist or access error
        }
        
        std::sort(certificates.begin(), certificates.end());
        return certificates;
    }

    void createDirectoryStructure() {
        cert_create_directory_structure();
    }

    // Status conversion utilities
    Status convertCStatus(cert_status_t cStatus) {
        switch (cStatus) {
            case CERT_STATUS_SUCCESS: return Status::Success;
            case CERT_STATUS_ERROR: return Status::Error;
            case CERT_STATUS_TIMEOUT: return Status::Timeout;
            case CERT_STATUS_INVALID_RESPONSE: return Status::InvalidResponse;
            case CERT_STATUS_FILE_ERROR: return Status::FileError;
            case CERT_STATUS_ALREADY_EXISTS: return Status::AlreadyExists;
            default: return Status::Error;
        }
    }

    cert_status_t convertCppStatus(Status cppStatus) {
        switch (cppStatus) {
            case Status::Success: return CERT_STATUS_SUCCESS;
            case Status::Error: return CERT_STATUS_ERROR;
            case Status::Timeout: return CERT_STATUS_TIMEOUT;
            case Status::InvalidResponse: return CERT_STATUS_INVALID_RESPONSE;
            case Status::FileError: return CERT_STATUS_FILE_ERROR;
            case Status::AlreadyExists: return CERT_STATUS_ALREADY_EXISTS;
            default: return CERT_STATUS_ERROR;
        }
    }

} // namespace CertificateAPI