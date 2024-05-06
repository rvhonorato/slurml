# slurml

![GitHub License](https://img.shields.io/github/license/rvhonorato/slurml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/64bf3bb285e44161ae19b0344c0d4ff3)](https://app.codacy.com/gh/rvhonorato/slurml/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![test](https://github.com/rvhonorato/slurml/actions/workflows/test.yml/badge.svg)](https://github.com/rvhonorato/slurml/actions/workflows/test.yml)

`slurml` is a RESTful service layer designed to enhance the functionality and security of small in-house HPC systems. Operating directly from a login node, `slurml` exposes HTTP endpoints that allow users to submit and manage payloads for execution via the Slurm scheduler without needing direct access to the computing nodes.

> 🚧🚧🚧🚧🚧🚧
>
> This project is still under heavy development. It's a re-write of an closed-source project being already used in the backend of the [WeNMR Portal](https://wenmr.science.uu.nl/) and its web-services
>
> 🚧🚧🚧🚧🚧🚧

## Key Features

- **HTTP Endpoint Integration**: Enables the submission and management of job payloads through simple HTTP requests, facilitating integration with various programming environments and tools.

- **Independent User Management**: Incorporates a robust user management system that enhances security by negating the need for users to log in directly to the HPC nodes. This system is tailored to maintain strict access controls and user authentication.

- **Seamless Slurm Integration**: Works in tandem with the existing Slurm scheduler, ensuring that job submissions and retrievals are handled efficiently and reliably.
Enhanced Security: By limiting direct node access, slurml significantly reduces the risk of unauthorized access and potential security vulnerabilities.

## Getting started

🚧 _coming soon_ 🚧

## Usage

🚧 _coming soon_ 🚧

## Contributing

🚧 _coming soon_ 🚧

## License

This project is licensed under the 0BSD license - see the [LICENSE](LICENSE) file for details.
