# Knock-knock: Access Control tool for CI/CD Environments

## Introduction
**Knock-knock** is a useful access control tool
designed for managing the NHN Kubernetes Service (NKS)-based CI/CD operating environment.
Named after the familiar act of knocking on a door :fist::fist::door::sweat_smile:,
this tool seeks to help ensure secure and efficient access management to CI/CD systems
for Cloud-Barista platform development.

## Background
In the era of cloud computing, it is important to secure your cloud infrastructure,
especially to prevent abnormal use of the Cloud-Barista platform and
mitigate risks associated with CSP credential exposure.
However, these concerns should not prevent the adoption of a very helpful CI/CD system.
Knock-knock helps Cloud-Barista maintainers solve this problem
by independently managing access control settings for their CI/CD environments.

## Features
- **User-Friendly Interface:** Offers an intuitive web interface for access rights administration.
- **Enhanced Security Integration:** Implements comprehensive security group and IP ACL management.
- **Integration with NHN Cloud API:** Manages resources like security groups and IP ACLs seamlessly.
- **SSO & Session Management:** Integrates Keycloak for Single Sign-On and secure user authentication.

## Functionalities
- **Security group management:** Enables creating, attaching, detaching, and removing rules for instances (VMs, virtual machines),
including inbound/outbound IP and port configurations.
- **IP access control list (ACL) management:** Facilitates creating, attaching, detaching, and removing IP ACL group and target
that can be bound to Load Balancer, including ALLOW/DENY and CIDR address configurations.

## Getting Started
### From Source Code
1. Clone the repository: `git clone https://github.com/cloud-barista/knock-knock.git`
2. Navigate to the directory: `cd knock-knock`
3. Create `config.yaml` and `secrets.yaml` in the directory `conf` by using provided templates
4. Build by `make`
5. Run `knock-knock` with `make run`

### Using Containers
1. Prepare `secrets.yaml`
2. Pull the Docker image: TBD
3. Run the container with `secrets.yaml`
```bash
docker run --mount type=bind,source="${PWD}"/secrets.yaml,target=/app/conf/ -p 8888:8888 -p 8057:8057 container_image
```
4. Access the web interface at `http://localhost:8888` or `http://your_domain_or_ip:8888`.

## Contributing
Contributions are welcome! Please see our [Contributing Guide](https://github.com/cloud-barista/docs/blob/master/CONTRIBUTING.md) for more information.

## License
Knock-knock is licensed under [Apache License 2.0](https://github.com/cloud-barista/docs/blob/master/LICENSE).
