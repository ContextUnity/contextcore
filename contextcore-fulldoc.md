# ContextCore: Shared Infrastructure

## Overview
ContextCore provides the fundamental contracts, security, and utilities shared across all microservices.

## Components
1.  **Security**:
    - `ContextToken`: Universal identity token.
    - `TokenBuilder`: Service-to-service auth.
2.  **Contracts (Protos)**:
    - `brain.proto`: Knowledge Store API.
    - `commerce.proto`: PIM API.
    - `router.proto`: Agent API.
3.  **Configuration**:
    - `BaseConfig`: Pydantic settings base.
    - `SharedConfig`: Logging, Env Management.

## Usage
All services MUST import `ContextToken` verification and use typed Protos for communication.
