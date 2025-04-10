#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "randomness/public_randomness.h"
#include "constraints/polynomial_constraints.h"
#include "proofs/proof_verification.h"

using json = nlohmann::json;

// Assuming these utility functions are declared in public_randomness.h
extern std::string getLatestEthereumBlockNumber();
extern std::string getCurrentTimestamp();
extern std::string sha256(const std::string& data);

int main() {
    // Initialize public randomness generator
    PublicRandomness pr;

    // Generate public randomness
    std::string randomValue = pr.generateRandomValue(10);
    std::cout << "Generated Public Randomness: " << randomValue << std::endl;

    // Combine JSON input, Ethereum block number, and timestamp
    std::string jsonField = "SampleInput";
    std::string combinedInput = jsonField + getLatestEthereumBlockNumber() + getCurrentTimestamp();
    std::string randomness = sha256(combinedInput);
    std::cout << "Combined Input Randomness (SHA256): " << randomness << std::endl;

    // Map computations to polynomial constraints
    libstark::PolynomialConstraints pc(2);
    std::vector<double> inputs = {1.0, 2.0};
    std::vector<double> polynomial = pc.arithmetize(inputs);
    std::cout << "Arithmetized Polynomial: ";
    for (double coeff : polynomial) {
        std::cout << coeff << " ";
    }
    std::cout << std::endl;

    // Placeholder for proof verification
    // ProofVerifier proofVerifier;
    // proofVerifier.initialize();
    // bool isValid = proofVerifier.verifyProof(polynomial);
    // std::cout << "Proof Verification Result: " << (isValid ? "Valid" : "Invalid") << std::endl;

    return 0;
}
