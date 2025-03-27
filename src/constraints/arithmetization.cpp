#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <chrono>

// SHA-256 hash function
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Simulates the polynomial-based proof generation
struct StarkProof {
    std::string commitment;
    std::string value;
};

// Function to simulate proof generation
StarkProof generateStarkProof(int x, int y, int w) {
    int a = x + y;               // Intermediate result
    int z = a * w;                // Final result

    // Polynomial constraints
    int P1 = a - (x + y);
    int P2 = z - (a * w);

    if (P1 != 0 || P2 != 0) {
        std::cerr << "Polynomial constraints do not hold!" << std::endl;
        exit(1);
    }

    // Commitments
    std::string commitment = sha256(std::to_string(a) + std::to_string(z));
    std::string value = std::to_string(z);

    return {commitment, value};
}

// Verifier function to check the proof
bool verifyStarkProof(const StarkProof& proof, int x, int y, int w) {
    int a = x + y;
    int z = a * w;

    // Regenerate the commitment
    std::string expectedCommitment = sha256(std::to_string(a) + std::to_string(z));

    return (proof.commitment == expectedCommitment && proof.value == std::to_string(z));
}

int main() {
    std::cout << "STARK-Like Polynomial Constraints Verification (Standalone) \n" << std::endl;

    // Step 1: Simulated computation
    int x = 3, y = 4, w = 2;
    std::cout << "Computation: z = (" << x << " + " << y << ") * " << w << std::endl;

    // Step 2: Generate the STARK proof
    std::cout << "\n[1] Generating STARK Proof..." << std::endl;
    StarkProof proof = generateStarkProof(x, y, w);

    std::cout << "Proof Commitment: " << proof.commitment << std::endl;
    std::cout << "Proof Value: " << proof.value << std::endl;

    // Step 3: Verify the proof
    std::cout << "\n[2] Verifying the STARK Proof..." << std::endl;
    if (verifyStarkProof(proof, x, y, w)) {
        std::cout << "STARK Proof Verified Successfully!" << std::endl;
    } else {
        std::cout << "STARK Proof Verification Failed!" << std::endl;
    }

    return 0;
}
