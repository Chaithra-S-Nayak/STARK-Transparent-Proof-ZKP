#ifndef POLYNOMIAL_CONSTRAINTS_H
#define POLYNOMIAL_CONSTRAINTS_H

#include <vector>
#include <string>
#include <cstddef>

namespace libstark
{

    // Represents a single polynomial constraint in the system
    struct Constraint
    {
        std::vector<double> coefficients;
        std::vector<int> variables;
        double constant;
    };

    class PolynomialConstraints
    {
    public:
        PolynomialConstraints(size_t numVars);

        // Add a constraint: poly(x) = 0
        void addConstraint(const std::vector<double> &coefficients,
                           const std::vector<int> &variables,
                           double constant = 0.0);

        // Check if a witness satisfies all constraints
        bool verifyWitness(const std::vector<double> &witness) const;

        // Evaluate a constraint at given witness point
        double evaluateConstraint(const Constraint &constraint,
                                  const std::vector<double> &witness) const;

        // Convert computational trace to witness polynomial
        std::vector<double> traceToPolynomial(const std::vector<double> &trace);

        // Get constraint system commitment (for verification)
        std::string getCommitment() const;

        // NEW: Evaluate constraints at random points for STARK proof
        std::vector<double> evaluateAtRandomPoints(
            const std::vector<double> &witness,
            const std::vector<std::string> &randomPoints) const;

    private:
        size_t numVars;
        std::vector<Constraint> constraints;

        // NEW: Convert string point to double for evaluation
        double pointToDouble(const std::string &point) const;
    };

} // namespace libstark

#endif // POLYNOMIAL_CONSTRAINTS_H