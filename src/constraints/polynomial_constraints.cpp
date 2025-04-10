#include "polynomial_constraints.h"
#include <cmath>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/evp.h>

namespace libstark
{

    PolynomialConstraints::PolynomialConstraints(size_t numVars) : numVars(numVars)
    {
        if (numVars == 0)
        {
            throw std::invalid_argument("Number of variables must be greater than zero");
        }
    }

    void PolynomialConstraints::addConstraint(const std::vector<double> &coefficients,
                                              const std::vector<int> &variables,
                                              double constant)
    {
        if (coefficients.size() != variables.size())
        {
            throw std::invalid_argument("Coefficient and variable vectors must have the same size");
        }

        for (int var : variables)
        {
            if (var < 0 || var >= static_cast<int>(numVars))
            {
                throw std::out_of_range("Variable index out of range");
            }
        }

        constraints.push_back({coefficients, variables, constant});
    }

    bool PolynomialConstraints::verifyWitness(const std::vector<double> &witness) const
    {
        if (witness.size() != numVars)
        {
            return false;
        }

        // Check if all constraints evaluate to zero (or very close to zero)
        for (const auto &constraint : constraints)
        {
            if (std::abs(evaluateConstraint(constraint, witness)) > 1e-10)
            {
                return false;
            }
        }

        return true;
    }

    // Modified evaluateConstraint function
    double PolynomialConstraints::evaluateConstraint(const Constraint &constraint,
                                                     const std::vector<double> &witness) const
    {
        double result = constraint.constant;

        for (size_t i = 0; i < constraint.coefficients.size(); ++i)
        {
            int varIndex = constraint.variables[i];
            result += constraint.coefficients[i] * witness[varIndex];
        }

        return result;
    }

    std::vector<double> PolynomialConstraints::traceToPolynomial(const std::vector<double> &trace)
    {
        // Simple lagrange interpolation for demonstration
        std::vector<double> polynomial(trace.size());

        // Copy trace as coefficients (simplified version)
        for (size_t i = 0; i < trace.size(); i++)
        {
            polynomial[i] = trace[i];
        }

        return polynomial;
    }

    std::string PolynomialConstraints::getCommitment() const
    {
        // Create a hash of all constraints
        std::stringstream ss;

        for (const auto &constraint : constraints)
        {
            // Add coefficients
            for (const auto &coeff : constraint.coefficients)
            {
                ss << std::fixed << std::setprecision(10) << coeff << ",";
            }
            ss << ";";

            // Add variables
            for (const auto &var : constraint.variables)
            {
                ss << var << ",";
            }
            ss << ";";

            // Add constant
            ss << std::fixed << std::setprecision(10) << constraint.constant << "|";
        }

        // Hash the serialized constraints
        std::string serialized = ss.str();

        // Simple SHA-256 hash
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length = 0;

        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, serialized.c_str(), serialized.length());
        EVP_DigestFinal_ex(mdctx, hash, &length);
        EVP_MD_CTX_free(mdctx);

        // Convert hash to hex string
        std::stringstream hexSS;
        for (unsigned int i = 0; i < length; i++)
        {
            hexSS << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return hexSS.str();
    }

    // Convert a random point string to a double value for evaluation
    double PolynomialConstraints::pointToDouble(const std::string &point) const
    {
        // Simple implementation for demo - in a real system you'd use a proper field
        // Take first 8 characters of hex and convert to double between 0 and 1
        std::string hexPart = point.substr(0, std::min(point.size(), size_t(8)));
        unsigned long value = std::stoul(hexPart, nullptr, 16);
        return static_cast<double>(value) / static_cast<double>(0xFFFFFFFF);
    }

    // Evaluate constraints at random points (for STARK proof)
    std::vector<double> PolynomialConstraints::evaluateAtRandomPoints(
        const std::vector<double> &witness,
        const std::vector<std::string> &randomPoints) const
    {

        std::vector<double> results;

        for (const auto &pointStr : randomPoints)
        {
            double x = pointToDouble(pointStr);

            // For each constraint, compute the result at this point
            double sumResult = 0.0;
            for (const auto &constraint : constraints)
            {
                double result = evaluateConstraint(constraint, witness);
                sumResult += result * result; // Square to make all errors positive
            }

            results.push_back(sumResult);
        }

        return results;
    }

} // namespace libstark