#include <iostream>
#include "randomness/public_randomness.h"
#include "constraints/polynomial_constraints.h"
#include "proofs/proof_verification.h"

int main() {
    // Initialize public randomness generator
    PublicRandomness pr;

    // Generate public randomness
    std::string randomValue = pr.generateRandomValue(10);
    std::cout << "Generated Public Randomness: " << randomValue << std::endl;

    // Map computations to polynomial constraints
    libstark::PolynomialConstraints pc(2);
    std::vector<double> inputs = {1.0, 2.0};
    std::vector<double> polynomial = pc.arithmetize(inputs);
    std::cout << "Arithmetized Polynomial: ";
    for (double coeff : polynomial) {
        std::cout << coeff << " ";
    }
    std::cout << std::endl;

    // Verify proofs (Placeholder, as ProofVerifier is not yet implemented)
    // ProofVerifier proofVerifier;
    // proofVerifier.initialize();
    // bool isValid = proofVerifier.verifyProof(polynomial);
    // std::cout << "Proof Verification Result: " << (isValid ? "Valid" : "Invalid") << std::endl;

    return 0;
}