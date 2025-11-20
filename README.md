🚛 SecureChain
==============

📖 Overview: Decentralized Proactive Supply Chain Fraud Detection
-----------------------------------------------------------------

The **SecureChain** smart application, written in the robust **Clarity** programming language, pioneers a decentralized, trust-minimized solution for global logistics. It serves as a **Proactive Supply Chain Fraud Detector** by implementing a sophisticated system for real-time risk assessment, immutable custody tracking, and behavioral monitoring across a network of registered participants. This application moves beyond reactive fraud reporting, integrating preventative controls directly into the transaction layer of the supply chain.

### Core Objectives of SecureChain:

-   **Mitigation of Systemic Risk:** By enforcing automated risk checks (`fraud-threshold`) at the point of shipment creation, the system actively blocks high-risk or potentially fraudulent transactions from entering the network.

-   **Trust and Transparency:** Every action, from registration to final delivery, contributes to an auditable, transparent record, utilizing a dynamic **Reputation Scoring System** to quantify the trustworthiness of each participant.

-   **Immutable Evidence:** Provides a cryptographically secure **Chain of Custody (CoC)** log, critical for legal and insurance purposes in the event of disputes or loss.

-   **AI/ML Integration Pathway:** Incorporates structures like `anomaly-patterns` and `risk-score` to establish clear data points necessary for future integration with off-chain Artificial Intelligence and Machine Learning models via Oracles.

* * * * *

⚙️ Application Architecture and Data Structures
-----------------------------------------------

SecureChain relies on a highly structured set of data maps and variables to maintain the comprehensive state of the supply chain network.

### I. Data Maps (Persistent Storage)

| **Map Name** | **Key Type** | **Value Structure** | **Purpose and Operational Significance** |
| --- | --- | --- | --- |
| `participants` | `principal` | `{ name: (string), reputation-score: uint, is-active: bool, ... }` | Stores the identity and performance metrics of all entities (manufacturers, carriers, distributors). The **Reputation Score** (u0-u100) is the core trust metric, dynamically adjusted based on successful deliveries and flagged incidents. |
| `shipments` | `uint` (Shipment ID) | `{ origin: principal, current-holder: principal, risk-score: uint, status: uint, is-flagged: bool, ... }` | The central registry for all tracked goods. It contains the pre-calculated **Risk Score**, which determines the initial threat level, and the current operational status of the shipment. |
| `custody-chain` | `{shipment-id: uint, sequence: uint}` | `{ holder: principal, timestamp: uint, location-hash: (buff 32), verified: bool }` | Records the immutable, sequential log of every transfer of accountability for the goods. The `location-hash` serves as a placeholder for verifiable proof of physical location. |
| `fraud-alerts` | `uint` (Alert ID) | `{ shipment-id: uint, reporter: principal, alert-type: (string), severity: uint, resolved: bool, ... }` | A dedicated incident log for all reported suspicious activities. Crucial for auditing and post-incident analysis. |
| `anomaly-patterns` | `principal` | `{ unusual-routes: uint, time-deviations: uint, value-discrepancies: uint, custody-gaps: uint, last-anomaly: uint }` | Tracks aggregate behavioral markers for each participant. These counts directly influence the `calculate-risk-score`, simulating inputs from sophisticated behavioral analytics tools. |

### II. State Variables (Global Counters and Controls)

| **Variable Name** | **Type** | **Purpose** | **Default Value/Range** |
| --- | --- | --- | --- |
| `shipment-counter` | `uint` | Tracks the total number of shipments created for unique ID generation. | `u0` (Starts at 1) |
| `alert-counter` | `uint` | Tracks the total number of fraud alerts generated. | `u0` (Starts at 1) |
| `fraud-threshold` | `uint` | The maximum permissible risk score for a shipment to be processed. Transaction is blocked if score meets or exceeds this value. | `u70` |

* * * * *

📝 Function Definitions: The Core Protocol
------------------------------------------

The operational logic is strictly segregated into public, private, and read-only interfaces, ensuring secure and predictable execution.

### I. Public Functions (`define-public`)

These functions represent the transactional core, requiring signing and capable of modifying the application state. They define the full lifecycle of a shipment.

| **Function** | **Access Control/Requirement** | **Execution Summary** |
| --- | --- | --- |
| `register-participant (name, participant-type)` | Any new Principal | Onboards a new entity. Asserts the sender is not already registered. Initializes `reputation-score` to a default value (`u75`) and sets `is-active: true`. |
| `create-shipment (destination, product-hash, declared-value)` | Registered, Trustworthy Participant | **Pre-emptive Fraud Check:** Calculates the **risk score** based on the sender's history and risk factors. The transaction **fails** with `err-fraud-detected` if the score is $\ge 70$. If approved, logs initial custody entry. |
| `transfer-custody (shipment-id, new-holder, location-hash)` | Current Holder of Shipment | Facilitates transfer of ownership. Asserts the sender is the current holder and the `new-holder` is `trustworthy`. Updates shipment status to `status-in-transit` and logs the new custody entry. |
| `report-fraud (shipment-id, alert-type, severity, description)` | Registered Participant | Allows participants to escalate concerns. Flags the shipment (`is-flagged: true`, `status: status-flagged`) and logs a formal, irreversible alert in the `fraud-alerts` map. |
| `complete-delivery (shipment-id, verification-hash)` | Destination Principal | Finalizes the supply chain segment. Asserts the sender is the intended recipient and the shipment is not flagged. **Triggers Reputation Rewards** for the Origin (+5) and the Destination (+3) for successful, non-disputed delivery. |

* * * * *

### II. Private Functions (`define-private`)

These internal utility functions ensure core business logic, risk modeling, and governance rules are applied consistently across public functions.

| **Function** | **Role** | **Mathematical/Logical Basis** |
| --- | --- | --- |
| `calculate-risk-score (participant, declared-value)` | **Risk Model Simulation** | Computes the total risk score (max 100). The formula heavily penalizes poor reputation and historical non-compliance: $\text{Risk} = (100 - \text{Reputation}) + (10 \cdot \text{Incidents}) + (5 \cdot \text{Anomaly Score})$. |
| `is-participant-trustworthy (participant)` | **Admission Control** | A binary check that verifies a participant meets the minimum operational standards: Must be `is-active: true`, maintain a reputation $\ge u50$, and have fewer than $u5$ flagged incidents. |
| `update-reputation (participant, score-change)` | **Reputation Engine** | Handles both positive and negative integer changes to a participant's score. Crucially, this function includes boundary protection to cap the score between $u0$ and $u100$. |

* * * * *

### III. Read-Only Functions (`define-read-only`)

These functions provide the necessary transparency and auditing capabilities, allowing any entity to query the immutable state of the supply chain without incurring transaction costs.

| **Function** | **Parameters** | **Returned Data** | **Value to Ecosystem** |
| --- | --- | --- | --- |
| `get-participant-details (participant principal)` | `principal` | `{ name, reputation-score, flagged-incidents, is-active, ... }` | Enables external auditors and potential partners to verify the current trust level and performance history of any participant. |
| `get-shipment-details (shipment-id uint)` | `uint` | `{ current-holder, status, risk-score, declared-value, is-flagged, ... }` | Provides real-time status and risk data on any shipment, enhancing visibility for logistics managers and customers. |
| `get-fraud-alert-details (alert-id uint)` | `uint` | `{ shipment-id, reporter, severity, description, resolved, ... }` | Offers access to the immutable history of reported incidents, critical for insurance claims and legal investigations. |
| `get-risk-score-details (participant principal) (declared-value uint)` | `principal`, `uint` | `(ok risk-score)` | Allows participants to simulate the current risk score for a potential shipment before transaction submission, facilitating proactive risk management. |
| `get-current-fraud-threshold` | None | `(ok fraud-threshold)` | Exposes the current, globally enforced maximum risk limit, providing full transparency into the application's core security parameter. |

* * * * *

🔒 Security Posture and Fraud Guardrails
----------------------------------------

SecureChain's security model is built on **prevention and accountability**.

### A. Transaction Blocking and Thresholds

The most critical security feature is the `fraud-threshold` check in `create-shipment`. By defining the maximum acceptable risk at $u70$ (configurable via future governance), the contract strictly enforces a security policy that prevents high-risk transactions from consuming network resources or jeopardizing the integrity of the supply chain.

### B. Accountability via Reputation

The `update-reputation` private function ensures that accountability is an intrinsic part of the process.

-   A high reputation is required for operation (`is-participant-trustworthy`).

-   Reputation increases automatically upon successful delivery (`complete-delivery`), creating a powerful on-chain incentive system.

-   Persistent negative behavior leads to low reputation, effectively creating an automated on-chain ban.

### C. CoC Integrity Enforcement

Before any transfer, the `transfer-custody` function asserts that the shipment is **not flagged** (`asserts! (not (get is-flagged shipment-data)) err-fraud-detected)`). This ensures that once a shipment is flagged for fraud, its movement is immediately frozen until the issue is resolved off-chain, preventing further movement of compromised goods.

* * * * *

🤝 Contribution and Development Roadmap
---------------------------------------

The SecureChain application is designed to evolve. We welcome expert contributions from the Clarity, logistics, and AI/ML communities.

### Key Roadmap Milestones:

1.  **Decentralized Oracle Integration:** Implement a mechanism to securely fetch and verify real-world data (e.g., GPS coordinates, temperature logs) to populate the `anomaly-patterns` map automatically, transforming the current simulation into real-time, verified risk scoring.

2.  **Dispute Resolution Module:** Build a sophisticated on-chain module to manage `status-disputed` shipments, potentially involving a staking mechanism, voting, and escrow to resolve issues without central authority.

3.  **Governance Mechanism:** Introduce a public function, secured by ownership or a staked voting system, to allow approved participants to propose changes to core parameters like the `fraud-threshold` or adjust the reputation reward/penalty coefficients.

* * * * *

📜 License
----------

```
MIT License

Copyright (c) 2025 SecureChain Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR TORT OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
