#ifndef POLYNOMIAL_CONSTRAINTS_H
#define POLYNOMIAL_CONSTRAINTS_H

#include <vector>
#include <cstddef>

namespace libstark {

class PolynomialConstraints {
public:
    PolynomialConstraints(size_t degree);

    std::vector<double> arithmetize(const std::vector<double>& inputs);
    bool verifyConstraints(const std::vector<double>& polynomial);
    std::vector<double> encodeOperation(const std::vector<double>& operands);

private:
    size_t degree;
};

} // namespace libstark

#endif // POLYNOMIAL_CONSTRAINTS_H