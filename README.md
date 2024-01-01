# RAPID: Rust Authentication with Post-quantum Identity in Distributed environments

This project is a Rust-based server-side application designed to run on Cloudflare Workers. It includes features for user authentication, session management, and secure token handling using post-quantum cryptography.

## Features

- User Registration and Login
- Secure Token Generation and Validation
- Session Management
- Post-Quantum Cryptographic Signatures with `pqc_dilithium`
- Async/Await Support for Non-Blocking Operations
- Integration with Cloudflare Workers

## Prerequisites

- Rust and Cargo
- Cloudflare Workers Account
- [wrangler](https://developers.cloudflare.com/workers/cli-wrangler/install-update) CLI for Cloudflare

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/kibernetikos/rapid.git
    cd rapid
    ```

2. Install dependencies:

    ```bash
    cargo update
    ```

## Configuration

Set up your environment variables in Cloudflare Workers according to your needs. The application requires the following environment configurations:

- D1

## Deployment

Deploy the application to Cloudflare Workers using the `wrangler` CLI:

```bash
npx wrangler deploy
```

## Usage

The application exposes the following endpoints:

- `POST /register`: Register a new user.
- `POST /login`: Authenticate a user and receive an access and refresh token.
- `GET /me`: Retrieve information about the currently authenticated user.

## Contributing

Contributions to this project are welcome. Please ensure to follow the code of conduct and contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Cloudflare Workers Team
- Contributors and maintainers of `pqc_dilithium` and other used Rust crates
