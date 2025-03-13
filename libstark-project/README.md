# LibSTARK Project

This project implements a transparent proof system using LibSTARK, which eliminates the need for a trusted setup phase. The main objectives of this project include generating public randomness, mapping computations to polynomial constraints, and verifying proofs.

## Project Structure

- **src/**: Contains the source code for the project.
  - **main.cpp**: Entry point for the application, initializing components for randomness generation, polynomial mapping, and proof verification.
  - **randomness/**: Implements functionality for generating public randomness.
    - **public_randomness.cpp**: Contains methods for creating verifiable random functions (VRFs) and obtaining unbiased public sources.
  - **constraints/**: Logic for mapping computations to polynomial constraints.
    - **polynomial_constraints.cpp**: Functions for arithmetization and encoding operations into polynomial representations.
  - **proofs/**: Handles proof generation and verification.
    - **proof_verification.cpp**: Methods for generating and verifying proofs using LibSTARK.
  - **utils/**: Provides utility functions for various operations.
    - **helpers.cpp**: Contains cryptographic functions and other helper methods.

- **CMakeLists.txt**: Configuration file for CMake, specifying project structure, dependencies, and build instructions.

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
   cd libstark-project
   ```

2. Build the project using CMake:
   ```
   mkdir build
   cd build
   cmake ..
   make
   ```

## Usage

After building the project, you can run the application by executing the compiled binary. The application will initialize the components and demonstrate the functionalities of generating public randomness, mapping computations, and verifying proofs.

## Objectives

- Implement a transparent proof system using LibSTARK.
- Generate public randomness that is unpredictable and tamper-resistant.
- Map computations to polynomial constraints for verification.
- Ensure the integrity of proofs through rigorous verification processes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.