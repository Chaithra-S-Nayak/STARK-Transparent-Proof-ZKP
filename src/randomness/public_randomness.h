#ifndef PUBLIC_RANDOMNESS_H
#define PUBLIC_RANDOMNESS_H

#include <string>
#include <vector>
#include <random>
#include <curl/curl.h>
#include <chrono>
#include <sstream>
#include <algorithm>

// Define RandomnessTracker class
class RandomnessTracker
{
public:
    void recordRandomnessGeneration(const std::string &source, const std::string &randomness)
    {
        history.push_back({source, randomness, getCurrentTimestamp()});
    }

    std::string getVerificationString() const
    {
        std::stringstream ss;
        for (const auto &entry : history)
        {
            ss << entry.source << ":" << entry.randomness << ":" << entry.timestamp << ";";
        }
        return ss.str();
    }

private:
    struct RandomnessEvent
    {
        std::string source;
        std::string randomness;
        uint64_t timestamp;
    };

    std::vector<RandomnessEvent> history;

    uint64_t getCurrentTimestamp()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }
};

class PublicRandomness
{
public:
    PublicRandomness();
    ~PublicRandomness();

    // Generate randomness using the formula: ρ=H(block_hash∥timestamp∥nonce)
    std::string generateTransparentRandomness();

    // Get vector of field elements for polynomial evaluation points
    std::vector<std::string> generateEvaluationPoints(
        const std::string &seed,
        int numPoints,
        const std::string &fieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    // Get randomness verification info for proof verification
    std::string getRandomnessProof() const;

private:
    std::mt19937 rng;
    CURL *curl = nullptr;
    RandomnessTracker randomnessTracker;
    const std::string API_KEY = "NIP5EJHPT47V37HX79H6W2P2PZ5S5ZWAA6";

    // Initialize CURL for HTTP requests
    void initializeCurl();

    // Generate a cryptographically secure nonce
    uint64_t generateNonce();

    // Get current timestamp in milliseconds
    uint64_t getCurrentTimestamp();

    // Callback function to write response data from curl
    static size_t writeCallback(void *contents, size_t size, size_t nmemb, std::string *userp);

    // Fetch the latest block hash from a blockchain API
    std::string fetchLatestBlockHash();

    // Get block hash from block number
    std::string getBlockHashFromNumber(const std::string &blockNumber);

    // Fallback method if blockchain API is unavailable
    // std::string fallbackBlockHash();

    // SHA-256 hash function
    std::string sha256Hash(const std::string &input);

    // Helper function to convert hex string to field element
    std::string convertToFieldElement(const std::string &hexStr, const std::string &modulus);
};

#endif // PUBLIC_RANDOMNESS_H