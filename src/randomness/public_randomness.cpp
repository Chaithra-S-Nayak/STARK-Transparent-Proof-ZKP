#include <iostream>
#include <random>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Helper function to write CURL response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Utility function to get latest Ethereum block number
std::string getLatestEthereumBlockNumber() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    std::string url = "https://api.etherscan.io/api?module=proxy&action=eth_blockNumber&apikey=NIP5EJHPT47V37HX79H6W2P2PZ5S5ZWAA6";

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    try {
        json resultJson = json::parse(readBuffer);
        if (resultJson.contains("result")) {
            std::string hexBlockNumber = resultJson["result"];
            unsigned long blockNumber = std::stoul(hexBlockNumber, nullptr, 16);
            return std::to_string(blockNumber);
        }
    } catch (...) {
        return "0";
    }

    return "0";
}

// Utility function to fetch the hash of a block using its number
std::string fetchLatestBlockHash(const std::string& blockNumberDecimal) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    // Convert decimal block number to hex for the API
    std::stringstream ss;
    ss << "0x" << std::hex << std::stoul(blockNumberDecimal);
    std::string hexBlockNumber = ss.str();

    std::string url = "https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag=" + hexBlockNumber + "&boolean=true&apikey=NIP5EJHPT47V37HX79H6W2P2PZ5S5ZWAA6";

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    try {
        json resultJson = json::parse(readBuffer);
        if (resultJson.contains("result") && resultJson["result"].contains("hash")) {
            return resultJson["result"]["hash"];
        }
    } catch (...) {
        return "0x0";
    }

    return "0x0";
}

// Main class to encapsulate randomness generation logic
class PublicRandomness {
public:
    std::string getEthereumBlockHashRandomness() {
        std::string latestBlockNumber = getLatestEthereumBlockNumber();
        std::string latestBlockHash = fetchLatestBlockHash(latestBlockNumber);

        std::cout << "Block Number: " << latestBlockNumber << std::endl;
        std::cout << "Block Hash: " << latestBlockHash << std::endl;

        return latestBlockHash;
    }
};

int main() {
    PublicRandomness pr;
    std::string randomness = pr.getEthereumBlockHashRandomness();
    std::cout << "Transparent Randomness (Block Hash): " << randomness << std::endl;

    return 0;
}
