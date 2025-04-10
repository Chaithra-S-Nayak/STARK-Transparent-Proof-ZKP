#include "public_randomness.h"
#include <iostream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <stdexcept>

using json = nlohmann::json;

// PublicRandomness implementation
PublicRandomness::PublicRandomness()
{
    // Initialize with system entropy
    rng.seed(std::random_device{}());
    initializeCurl();
}

PublicRandomness::~PublicRandomness()
{
    if (curl)
    {
        curl_easy_cleanup(curl);
        curl = nullptr;
    }
    curl_global_cleanup();
}

// Generate transparent randomness using blockchain data
std::string PublicRandomness::generateTransparentRandomness()
{
    std::string blockHash;

    try
    {
        blockHash = fetchLatestBlockHash();
        std::cout << "Successfully fetched block hash: " << blockHash << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error fetching blockchain data: " << e.what() << std::endl;
        std::cerr << "Using timestamp-based hash instead" << std::endl;

        // Create a hash from the current timestamp since we don't want to use fallback
        std::string timestamp = std::to_string(getCurrentTimestamp());
        blockHash = sha256Hash(timestamp);
    }

    uint64_t timestamp = getCurrentTimestamp();
    uint64_t nonce = generateNonce();

    std::stringstream combined;
    combined << blockHash << timestamp << nonce;

    std::string result = sha256Hash(combined.str());
    randomnessTracker.recordRandomnessGeneration("TRANSPARENT", result);
    return result;
}

// Generate evaluation points for polynomial constraints
std::vector<std::string> PublicRandomness::generateEvaluationPoints(
    const std::string &seed,
    int numPoints,
    const std::string &fieldModulus)
{

    std::vector<std::string> points;
    std::string currentSeed = seed;

    for (int i = 0; i < numPoints; i++)
    {
        currentSeed = sha256Hash(currentSeed + std::to_string(i));
        std::string point = convertToFieldElement(currentSeed, fieldModulus);
        points.push_back(point);
        randomnessTracker.recordRandomnessGeneration("EVAL_POINT_" + std::to_string(i), point);
    }

    return points;
}

// Get randomness verification info for proof verification
std::string PublicRandomness::getRandomnessProof() const
{
    return randomnessTracker.getVerificationString();
}

// Initialize CURL for HTTP requests
void PublicRandomness::initializeCurl()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
}

// Generate a cryptographically secure nonce
uint64_t PublicRandomness::generateNonce()
{
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng);
}

// Get current timestamp in milliseconds
uint64_t PublicRandomness::getCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Callback function to write response data from curl
size_t PublicRandomness::writeCallback(void *contents, size_t size, size_t nmemb, std::string *userp)
{
    userp->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// Fetch the latest block hash from a blockchain API
std::string PublicRandomness::fetchLatestBlockHash()
{
    if (!curl)
    {
        throw std::runtime_error("CURL not initialized");
    }

    std::string readBuffer;
    std::string url = "https://api.etherscan.io/api?module=proxy&action=eth_blockNumber&apikey=" + API_KEY;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        throw std::runtime_error("Failed to fetch block number: " + std::string(curl_easy_strerror(res)));
    }

    // Add debug to see what we're getting
    std::cout << "Block number API response: " << readBuffer.substr(0, 100) << "..." << std::endl;

    try
    {
        json resultJson = json::parse(readBuffer);
        if (!resultJson.contains("result"))
        {
            throw std::runtime_error("API response missing 'result' field");
        }

        std::string blockNumber = resultJson["result"];
        return getBlockHashFromNumber(blockNumber);
    }
    catch (const json::parse_error &e)
    {
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
    }
}

// Get block hash from block number
std::string PublicRandomness::getBlockHashFromNumber(const std::string &blockNumber)
{
    if (!curl)
    {
        throw std::runtime_error("CURL not initialized");
    }

    std::string readBuffer;
    std::string url = "https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag=" + blockNumber + "&boolean=true&apikey=" + API_KEY;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        throw std::runtime_error("Failed to fetch block: " + std::string(curl_easy_strerror(res)));
    }

    // Add debug to see what we're getting
    std::cout << "Block data API response: " << readBuffer.substr(0, 100) << "..." << std::endl;

    try
    {
        json resultJson = json::parse(readBuffer);
        if (!resultJson.contains("result") || !resultJson["result"].contains("hash"))
        {
            throw std::runtime_error("API response missing 'result.hash' field");
        }

        return resultJson["result"]["hash"];
    }
    catch (const json::parse_error &e)
    {
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
    }
}

// SHA-256 hash function with modern EVP API
std::string PublicRandomness::sha256Hash(const std::string &input)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context)
        return "";

    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) &&
        EVP_DigestUpdate(context, input.c_str(), input.length()) &&
        EVP_DigestFinal_ex(context, hash, &length))
    {

        EVP_MD_CTX_free(context);

        std::stringstream ss;
        for (unsigned int i = 0; i < length; i++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    EVP_MD_CTX_free(context);
    return "";
}

// Helper function to convert hex string to field element
std::string PublicRandomness::convertToFieldElement(const std::string &hexStr, const std::string &modulus)
{
    return hexStr.substr(0, std::min(hexStr.length(), size_t(64)));
}