# LibSTARK Project

This project implements a **transparent proof system** using LibSTARK, which eliminates the need for a trusted setup phase. The main objectives of this project include generating public randomness, mapping computations to polynomial constraints, and verifying proofs.

## Objectives

- **Transparent Proof System**: Implement a proof system that does not rely on a trusted setup.
- **Public Randomness Generation**: Generate randomness that is unpredictable, tamper-resistant, and verifiable.
- **Polynomial Constraints Mapping**: Transform computations into polynomial constraints for efficient verification.
- **Proof Generation and Verification**: Ensure the integrity of proofs through rigorous verification processes.

## Project Structure

- **src/**: Contains the source code for the project.
  - **randomness/**: Implements functionality for generating public randomness.
    - **public_randomness.cpp**: Methods for creating verifiable random functions (VRFs) and obtaining unbiased public sources.
  - **constraints/**: Logic for mapping computations to polynomial constraints.
    - **arithmetization.cpp**: Functions for arithmetization and encoding operations into polynomial representations.
  - **proofs/**: Handles proof generation and verification.
    - **proof_verification.cpp**: Methods for generating and verifying proofs using LibSTARK.
  - **utils/**: Provides utility functions for various operations.
    - **helpers.cpp**: Contains cryptographic functions and other helper methods.

- **CMakeLists.txt**: Configuration file for CMake, specifying project structure, dependencies, and build instructions.
- **README.md**: Documentation for the project, including setup instructions, usage, and objectives.