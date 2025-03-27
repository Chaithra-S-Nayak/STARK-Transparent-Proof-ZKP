#ifndef PUBLIC_RANDOMNESS_H
#define PUBLIC_RANDOMNESS_H

#include <string>
#include <vector>
#include <random>
#include <curl/curl.h>

// Forward declaration of RandomnessTracker
class RandomnessTracker;

class PublicRandomness {
public:
    PublicRandomness();
    ~PublicRandomness();

    // Core randomness generation methods
    std::string generateTransparentRandomness();
    std::string generateVRF(const std::string& privateKey, const std::string& input);
    std::string generateFieldCompatibleVRF(const std::string& privateKey, 
                                          const std::string& input, 
                                          const std::string& fieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617");
    std::string generateCombinedRandomness(const std::string& privateKey);
    
    // STARK-specific randomness methods
    std::vector<std::string> generateFRIRandomness(const std::string& initialRandomness, int numRounds);
    std::string generateStarkRandomness(const std::string& transcript);
    std::vector<std::string> generateEvaluationPoints(const std::string& seed, 
                                                     int numPoints, 
                                                     const std::string& fieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617");
    
    // Verification methods
    bool verifyVRF(const std::string& publicKey, const std::string& input, 
                  const std::string& output, const std::string& proof);
    std::string getRandomnessProof() const;

private:
    std::mt19937 rng;
    CURL* curl;
    const std::string characters;
    RandomnessTracker randomnessTracker;
    
    // Private helper methods
    void initializeCurl();
    uint64_t generateNonce();
    uint64_t getCurrentTimestamp();
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* userp);
    std::string fetchLatestBlockHash();
    std::string fallbackBlockHash();
    std::string sha256Hash(const std::string& input);
    std::string convertToFieldElement(const std::string& hexStr, const std::string& modulus);
};

// Also declare RandomnessTracker class since it's used by PublicRandomness
class RandomnessTracker {
public:
    void recordRandomnessGeneration(const std::string& source, const std::string& randomness);
    std::string getVerificationString() const;
    
private:
    struct RandomnessEvent {
        std::string source;
        std::string randomness;
        uint64_t timestamp;
    };
    
    std::vector<RandomnessEvent> history;
    uint64_t getCurrentTimestamp();
};

#endif // PUBLIC_RANDOMNESS_H