# Medical Record Wallet App - Quick Setup

## Prerequisites

- **C++ Compiler** (Xcode on macOS, GCC on Linux, Visual Studio on Windows)
- **CMake 3.16+**
- **Qt6**

## Installation

### macOS

```bash
brew install cmake qt6
```

### Windows

- Install Visual Studio 2019+
- Download Qt6 from [qt.io](https://www.qt.io/download)
- Install CMake from [cmake.org](https://cmake.org/download/)

## Build & Run

```bash
# Clone and build
git clone https://github.com/Durvalm/MedicalRecordWalletApp.git
cd MedicalRecordWalletApp
mkdir build && cd build

# Configure (add Qt6 path if needed)
cmake ..

# Build
cmake --build .

# Run
./MedicalRecordWalletApp  # macOS/Linux
# or
MedicalRecordWalletApp.exe  # Windows
```

## Troubleshooting

**CMake can't find Qt6?**

- macOS: `cmake .. -DCMAKE_PREFIX_PATH=/opt/homebrew/lib/cmake/Qt6`
- Windows: `cmake .. -DCMAKE_PREFIX_PATH="C:/Qt/6.x.x/msvc2019_64/lib/cmake/Qt6"`

**Still having issues?** honestly, use ChatGpt, if there's any issue where the compiler can't find the libraries, it's kinda difficult to troubleshoot

---

## Project Architecture: Medical Record Wallet 🧬

---

### 1. Project Overview & Problem Statement

The **Medical Record Wallet** is a desktop application that allows patients to securely store and retrieve their medical records. Medical records contain highly sensitive personal information, and traditional storage solutions often leave patients vulnerable to data leaks. This project's goal is to build a secure, user-friendly wallet where patients retain full control over their data using a modern hybrid cryptographic scheme.

- **MVP Scope**: Patients can encrypt and locally save their medical records. They can then decrypt and view their records after authenticating.
- **Core Technology**: The system will use **AES-256** for file encryption and **RSA** for key encryption.

---

### 2. Cryptographic Workflow

The system uses a hybrid approach to combine the speed of symmetric encryption with the security of asymmetric encryption.

- **Key Generation**: Each user has a unique RSA key pair (2048-bit minimum). Their private key is encrypted and protected by a password using **PBKDF2**.

- **Encryption (Storing a Record)**:

  1.  A new, random **AES-256 session key** is generated for the file.
  2.  The medical record is encrypted using the AES key (preferably in **AES-GCM mode** to ensure both confidentiality and integrity).
  3.  The AES session key is then encrypted using the user's **public RSA key**.
  4.  The encrypted file and the encrypted AES key are stored.

- **Decryption (Viewing a Record)**:
  1.  The user provides their password to decrypt their **private RSA key**.
  2.  The private RSA key is used to decrypt the AES session key.
  3.  The recovered AES key is then used to decrypt the medical record.

---

## Requirements from the professor

Implement a hybrid cryptographic scheme (both private-key and public-key) using a programming language that you are comfortable with.

---

## Guideline:

1.  You may use existing crypto packages for some parts, e.g., to generate large primes.

2.  It is better to use **C++** or **Java** for this program; e.g., you can use the **Crypto++ Library**.

3.  The minimum size of your numbers should be **256 bits**.

4.  It would be great if you create a **GUI** (Graphical User Interface) for your program.

5.  Finally, prepare a one-page description regarding the architecture of your code.
