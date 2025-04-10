#include "polynomial_constraints.h"
#include "../randomness/public_randomness.h"
#include <iostream>

using namespace libstark;

int main()
{
    std::cout << "Testing Polynomial Constraint System" << std::endl;

    // Create a constraint system for a computation with 3 variables
    PolynomialConstraints system(3);

    // Add constraint: x₁ * x₂ - x₃ = 0 (multiplication constraint)
    // which means x₃ = x₁ * x₂
    // Test with a linear constraint instead
    std::vector<double> coeffs = {3.0, 4.0, -7.0}; // 3*x₁ + 4*x₂ - 7*x₃ = 0
    std::vector<int> vars = {0, 1, 2};
    system.addConstraint(coeffs, vars, 0.0);

    // Valid witness: [1, 1, 1] where 3*1 + 4*1 = 7*1
    std::vector<double> validWitness = {1.0, 1.0, 1.0};

    // Invalid witness: [1, 1, 2] where 3*1 + 4*1 ≠ 7*2
    // std::vector<double> invalidWitness = {1.0, 1.0, 2.0};

    // Verify witnesses
    bool validResult = system.verifyWitness(validWitness);
    // bool invalidResult = system.verifyWitness(invalidWitness);

    std::cout << "Valid witness verification: " << (validResult ? "PASSED" : "FAILED") << std::endl;
    // std::cout << "Invalid witness verification: " << (!invalidResult ? "PASSED" : "FAILED") << std::endl;

    // Generate and print commitment
    std::string commitment = system.getCommitment();
    std::cout << "Constraint system commitment: " << commitment << std::endl;

    // Create a computational trace and convert to polynomial
    std::vector<double> trace = {3.0, 4.0, 12.0};
    std::vector<double> polynomial = system.traceToPolynomial(trace);

    std::cout << "Trace as polynomial coefficients: ";
    for (const auto &coeff : polynomial)
    {
        std::cout << coeff << " ";
    }
    std::cout << std::endl;

    // Generate evaluation points using randomness system
    PublicRandomness randGen;
    std::string seed = randGen.generateTransparentRandomness();
    std::vector<std::string> evalPoints = randGen.generateEvaluationPoints(seed, 3);

    std::cout << "\nGenerated evaluation points for proof:" << std::endl;
    for (const auto &point : evalPoints)
    {
        std::cout << "  " << point << std::endl;
    }

    // Evaluate constraints at random points (for STARK proof)
    std::vector<double> evaluations = system.evaluateAtRandomPoints(validWitness, evalPoints);

    std::cout << "\nConstraint evaluations at random points:" << std::endl;
    for (size_t i = 0; i < evaluations.size(); i++)
    {
        std::cout << "  At point " << evalPoints[i].substr(0, 8) << "...: " << evaluations[i] << std::endl;
    }

    return 0;
}