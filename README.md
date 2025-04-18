# LibSTARK Project

This project implements a **transparent proof system** using LibSTARK, which eliminates the need for a trusted setup phase. The main objectives of this project include generating public randomness, mapping computations to polynomial constraints, and verifying proofs.

## Objectives

- **Transparent Proof System**: Implement a proof system that does not rely on a trusted setup.
- **Public Randomness Generation**: Generate randomness that is unpredictable, tamper-resistant, and verifiable.
- **Polynomial Constraints Mapping**: Transform computations into polynomial constraints for efficient verification.
- **Proof Generation and Verification**: Ensure the integrity of proofs through rigorous verification processes.

## Project Structure

- **src/**: Contains the source code for the project.
  - **randomness/**: Handles generation of public randomness.
    - **public_randomness.h**: Defines the `PublicRandomness` class for generating transparent randomness.
    - **public_randomness.cpp**: Implements blockchain-based randomness generation.
  - **constraints/**: Defines and evaluates polynomial constraints.
    - **polynomial_constraints.h**: Defines the `PolynomialConstraints` class for constraint handling.
    - **polynomial_constraints.cpp**: Implements constraint evaluation and verification logic.
    - **test_polynomial_constraints.cpp**: Test cases for the polynomial constraint functionality.

- **CMakeLists.txt**: Configuration file for CMake, specifying project structure, dependencies, and build instructions.
