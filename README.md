# 🎓 Digitally Validate a University Degree

A Rust-based CLI application to issue, present, and verify academic credentials using [IOTA Identity Framework](https://docs.iota.org/iota-identity). This project demonstrates how to create and validate Verifiable Credentials (VCs) and Verifiable Presentations (VPs) using the IOTA Identity framework — entirely through the command line.

---

## 🚀 Features

- ✅ **DID Creation** for issuer and holder identities
- 📜 **Issue Verifiable Credential** in JWT format
- 🧾 **Create and Sign Verifiable Presentations**
- 🔍 **Validate Presentations and Credentials**
- 🔐 Built using IOTA Identity SDK + DIDComm principles

---

## 🛠 Requirements

- Rust (latest)
- cargo (latest)
- Internet connection (for IOTA Identity client resolution)
- for running example: a local network node with the IOTA identity package deployed as described [here](https://docs.iota.org/iota-identity/getting-started/local-network-setup)

---

## 📦 Installation

1. **Clone this repository:**

```bash
git clone https://github.com/your-username/digitally_validate_degree.git
cd digitally_validate_degree

2. **Install dependencies**

```bash
cargo build

## 🧪 Usage

- **issuer.rs:** Creates a VC and outputs it as a JWT
- **holder.rs:** Takes a VC JWT and creates a signed VP JWT
- **verifier.rs:** Takes a VP JWT and validates it

1. **Run the Issuer

```bash
cargo run --bin issuer

This prints a VC JWT. Copy this JWT.

2. **Run the Holder (with VC JWT input)

```bash
cargo run --bin holder -- --vc "<PASTE_VC_JWT_HERE>"

This signs a Verifiable Presentation and outputs the VP JWT.

3. **Run the Verifier (with VP JWT input)**

```bash
cargo run --bin verifier -- --vp "<PASTE_VP_JWT_HERE>"

This validates the presentation and prints the validated data.

## 🧠 Concepts Used

- Verifiable Credentials (VCs): Digitally signed claims from an issuer
- Verifiable Presentations (VPs): Holder-generated proofs containing VCs
- DIDs (Decentralized Identifiers): Self-sovereign identity management
- JWT Signatures: Secure and tamper-proof identity tokens

## 🙌 Acknowledgements

- [IOTA Identity Rust](https://docs.iota.org/iota-identity/getting-started/rust)
- Original example code adapted from the [IOTA Identity examples](https://github.com/iotaledger/identity/tree/main/examples)
