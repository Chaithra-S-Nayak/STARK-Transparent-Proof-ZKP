#ifndef PUBLIC_RANDOMNESS_H
#define PUBLIC_RANDOMNESS_H

#include <string>
#include <random> // Include the random header

class PublicRandomness {
public:
    PublicRandomness();
    std::string generateRandomValue(size_t length);
    std::string getBlockchainHash();
    std::string generateVerifiableRandomFunction();

private:
    std::mt19937 rng; // Use std::mt19937 for random number generation
    const std::string characters;
};

#endif // PUBLIC_RANDOMNESS_H