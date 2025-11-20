;; Proactive Supply Chain Fraud Detector
;; This smart contract provides a comprehensive fraud detection system for supply chain management.
;; It tracks shipments, verifies participants, monitors anomalies, and flags suspicious activities
;; to prevent fraud in real-time across the supply chain network.

;; constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-unauthorized (err u102))
(define-constant err-already-exists (err u103))
(define-constant err-invalid-status (err u104))
(define-constant err-fraud-detected (err u105))
(define-constant err-participant-suspended (err u106))
(define-constant err-invalid-threshold (err u107))

;; Fraud risk levels
(define-constant risk-level-low u1)
(define-constant risk-level-medium u2)
(define-constant risk-level-high u3)
(define-constant risk-level-critical u4)

;; Shipment status codes
(define-constant status-created u1)
(define-constant status-in-transit u2)
(define-constant status-delivered u3)
(define-constant status-disputed u4)
(define-constant status-flagged u5)

;; data maps and vars

;; Track registered participants in the supply chain
(define-map participants
    principal
    {
        name: (string-ascii 50),
        participant-type: (string-ascii 20),
        reputation-score: uint,
        total-shipments: uint,
        flagged-incidents: uint,
        is-active: bool,
        registered-at: uint
    }
)

;; Track shipments with detailed information
(define-map shipments
    uint
    {
        shipment-id: uint,
        origin: principal,
        current-holder: principal,
        destination: principal,
        product-hash: (buff 32),
        declared-value: uint,
        status: uint,
        risk-score: uint,
        created-at: uint,
        last-updated: uint,
        is-flagged: bool
    }
)

;; Track custody chain for each shipment
(define-map custody-chain
    {shipment-id: uint, sequence: uint}
    {
        holder: principal,
        timestamp: uint,
        location-hash: (buff 32),
        verified: bool
    }
)

;; Track fraud alerts and incidents
(define-map fraud-alerts
    uint
    {
        alert-id: uint,
        shipment-id: uint,
        reporter: principal,
        alert-type: (string-ascii 50),
        severity: uint,
        description: (string-ascii 200),
        timestamp: uint,
        resolved: bool
    }
)

;; Track anomaly patterns for ML-based detection
(define-map anomaly-patterns
    principal
    {
        unusual-routes: uint,
        time-deviations: uint,
        value-discrepancies: uint,
        custody-gaps: uint,
        last-anomaly: uint
    }
)

;; Global counters
(define-data-var shipment-counter uint u0)
(define-data-var alert-counter uint u0)
(define-data-var fraud-threshold uint u70)

;; private functions

;; Calculate risk score based on multiple factors
(define-private (calculate-risk-score (participant principal) (declared-value uint))
    (let
        (
            (participant-data (unwrap! (map-get? participants participant) u100))
            (anomaly-data (default-to 
                {unusual-routes: u0, time-deviations: u0, value-discrepancies: u0, custody-gaps: u0, last-anomaly: u0}
                (map-get? anomaly-patterns participant)))
            (reputation (get reputation-score participant-data))
            (incidents (get flagged-incidents participant-data))
            (anomaly-score (+ (get unusual-routes anomaly-data) 
                            (get time-deviations anomaly-data)
                            (get value-discrepancies anomaly-data)
                            (get custody-gaps anomaly-data)))
        )
        ;; Risk calculation: lower reputation + more incidents + anomalies = higher risk
        (+ (- u100 reputation) (* incidents u10) (* anomaly-score u5))
    )
)

;; Check if participant is trustworthy
(define-private (is-participant-trustworthy (participant principal))
    (match (map-get? participants participant)
        participant-data (and 
            (get is-active participant-data)
            (>= (get reputation-score participant-data) u50)
            (< (get flagged-incidents participant-data) u5))
        false
    )
)

;; Update participant reputation based on behavior
(define-private (update-reputation (participant principal) (score-change int))
    (match (map-get? participants participant)
        participant-data
            (let
                (
                    (current-score (get reputation-score participant-data))
                    (new-score (if (< score-change 0)
                        (if (> current-score (to-uint (- 0 score-change)))
                            (- current-score (to-uint (- 0 score-change)))
                            u0)
                        (+ current-score (to-uint score-change))))
                )
                (map-set participants participant
                    (merge participant-data {reputation-score: new-score}))
                (ok new-score)
            )
        err-not-found
    )
)

;; public functions

;; Register a new participant in the supply chain
(define-public (register-participant (name (string-ascii 50)) (participant-type (string-ascii 20)))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (is-none (map-get? participants caller)) err-already-exists)
        (ok (map-set participants caller
            {
                name: name,
                participant-type: participant-type,
                reputation-score: u75,
                total-shipments: u0,
                flagged-incidents: u0,
                is-active: true,
                registered-at: block-height
            }))
    )
)

;; Create a new shipment with fraud detection checks
(define-public (create-shipment (destination principal) (product-hash (buff 32)) (declared-value uint))
    (let
        (
            (caller tx-sender)
            (new-shipment-id (+ (var-get shipment-counter) u1))
            (risk-score (calculate-risk-score caller declared-value))
        )
        (asserts! (is-some (map-get? participants caller)) err-unauthorized)
        (asserts! (is-participant-trustworthy caller) err-participant-suspended)
        (asserts! (< risk-score (var-get fraud-threshold)) err-fraud-detected)
        
        (var-set shipment-counter new-shipment-id)
        
        (map-set shipments new-shipment-id
            {
                shipment-id: new-shipment-id,
                origin: caller,
                current-holder: caller,
                destination: destination,
                product-hash: product-hash,
                declared-value: declared-value,
                status: status-created,
                risk-score: risk-score,
                created-at: block-height,
                last-updated: block-height,
                is-flagged: (>= risk-score u50)
            })
        
        (map-set custody-chain {shipment-id: new-shipment-id, sequence: u0}
            {
                holder: caller,
                timestamp: block-height,
                location-hash: product-hash,
                verified: true
            })
        
        (ok new-shipment-id)
    )
)

;; Transfer shipment custody with verification
(define-public (transfer-custody (shipment-id uint) (new-holder principal) (location-hash (buff 32)))
    (let
        (
            (caller tx-sender)
            (shipment-data (unwrap! (map-get? shipments shipment-id) err-not-found))
            (current-holder (get current-holder shipment-data))
            (sequence (get total-shipments (unwrap! (map-get? participants new-holder) err-not-found)))
        )
        (asserts! (is-eq caller current-holder) err-unauthorized)
        (asserts! (is-participant-trustworthy new-holder) err-participant-suspended)
        (asserts! (not (get is-flagged shipment-data)) err-fraud-detected)
        
        (map-set shipments shipment-id
            (merge shipment-data {
                current-holder: new-holder,
                last-updated: block-height,
                status: status-in-transit
            }))
        
        (map-set custody-chain {shipment-id: shipment-id, sequence: (+ sequence u1)}
            {
                holder: new-holder,
                timestamp: block-height,
                location-hash: location-hash,
                verified: false
            })
        
        (ok true)
    )
)

;; Verify and complete shipment delivery
(define-public (complete-delivery (shipment-id uint) (verification-hash (buff 32)))
    (let
        (
            (caller tx-sender)
            (shipment-data (unwrap! (map-get? shipments shipment-id) err-not-found))
            (destination (get destination shipment-data))
        )
        (asserts! (is-eq caller destination) err-unauthorized)
        (asserts! (not (get is-flagged shipment-data)) err-fraud-detected)
        
        (map-set shipments shipment-id
            (merge shipment-data {
                status: status-delivered,
                last-updated: block-height
            }))
        
        (try! (update-reputation (get origin shipment-data) 5))
        (try! (update-reputation caller 3))
        
        (ok true)
    )
)


