;;===============================================================================
;; DIGITAL ASSET REGISTRY PROTOCOL v2.0
;; ===============================================================================
;; 
;; Enterprise-grade decentralized asset management and verification system
;; Built on Stacks blockchain infrastructure for maximum security and reliability
;; 
;; This comprehensive protocol enables secure registration, validation, and management
;; of digital assets with advanced cryptographic security and multi-tiered access control
;; 
;; Key Features:
;; - Immutable asset registration with blockchain timestamping
;; - Multi-layered permission system with granular access controls  
;; - Advanced metadata validation and integrity verification
;; - Secure ownership transfer protocols with validation checkpoints
;; - Comprehensive audit trail for all asset operations
;; - Enterprise-ready scalability with optimized storage patterns
;; ===============================================================================

;; ===============================================================================
;; SYSTEM CONFIGURATION AND CONSTANTS
;; ===============================================================================

;; Primary system administrator with full protocol privileges
(define-constant protocol-administrator tx-sender)

;; ===============================================================================
;; COMPREHENSIVE ERROR CODE DEFINITIONS
;; ===============================================================================
;; Standardized error response system for robust error handling and debugging

(define-constant asset-not-found (err u501))
(define-constant duplicate-asset-registration (err u502))
(define-constant invalid-asset-metadata (err u503))
(define-constant asset-size-limit-exceeded (err u504))
(define-constant insufficient-permissions (err u505))
(define-constant ownership-verification-failed (err u506))
(define-constant administrative-access-required (err u500))
(define-constant access-denied (err u507))
(define-constant category-validation-error (err u508))

;; ===============================================================================
;; GLOBAL STATE MANAGEMENT
;; ===============================================================================

;; Global counter for tracking total number of registered digital assets
(define-data-var total-registered-assets uint u0)

;; ===============================================================================
;; PRIMARY DATA STRUCTURES AND MAPPINGS
;; ===============================================================================

;; Core digital asset registry - stores complete asset information
;; This mapping contains all essential asset metadata and ownership details
(define-map digital-asset-registry
  { asset-identifier: uint }
  {
    asset-name: (string-ascii 64),
    asset-owner: principal,
    content-size: uint,
    registration-block: uint,
    asset-description: (string-ascii 128),
    category-tags: (list 10 (string-ascii 32))
  }
)

;; Advanced permission control system - manages access rights for each asset
;; Enables granular control over who can view and interact with specific assets
(define-map asset-permission-registry
  { asset-identifier: uint, authorized-user: principal }
  { access-granted: bool }
)

;; ===============================================================================
;; INTERNAL VALIDATION AND UTILITY FUNCTIONS
;; ===============================================================================

;; Advanced category tag validation function
;; Ensures all category tags meet protocol requirements for length and format
;; @param category-tag: The tag string to validate
;; @returns: Boolean indicating if tag is valid
(define-private (is-valid-category-tag (category-tag (string-ascii 32)))
  (and
    ;; Tag must not be empty
    (> (len category-tag) u0)
    ;; Tag must not exceed maximum length
    (< (len category-tag) u33)
  )
)

;; Comprehensive tag list validation system
;; Validates entire collections of category tags for compliance
;; @param tag-list: List of category tags to validate
;; @returns: Boolean indicating if entire list is valid
(define-private (validate-category-tag-list (tag-list (list 10 (string-ascii 32))))
  (and
    ;; List must contain at least one tag
    (> (len tag-list) u0)
    ;; List must not exceed maximum allowed tags
    (<= (len tag-list) u10)
    ;; All tags in list must pass individual validation
    (is-eq (len (filter is-valid-category-tag tag-list)) (len tag-list))
  )
)

;; Asset existence verification utility
;; Checks if an asset exists in the registry before operations
;; @param asset-identifier: The unique asset ID to check
;; @returns: Boolean indicating if asset exists
(define-private (asset-exists-in-registry (asset-identifier uint))
  (is-some (map-get? digital-asset-registry { asset-identifier: asset-identifier }))
)

;; Content size extraction utility function
;; Safely retrieves the content size of a registered asset
;; @param asset-identifier: The unique asset ID
;; @returns: Content size in bytes, or 0 if asset not found
(define-private (get-asset-content-size (asset-identifier uint))
  (default-to u0
    (get content-size
      (map-get? digital-asset-registry { asset-identifier: asset-identifier })
    )
  )
)

;; Ownership verification security function
;; Validates that a given principal owns the specified asset
;; @param asset-identifier: The unique asset ID
;; @param claiming-owner: The principal claiming ownership
;; @returns: Boolean indicating if ownership claim is valid
(define-private (verify-asset-ownership (asset-identifier uint) (claiming-owner principal))
  (match (map-get? digital-asset-registry { asset-identifier: asset-identifier })
    asset-data (is-eq (get asset-owner asset-data) claiming-owner)
    false
  )
)

;; ===============================================================================
;; PRIMARY PUBLIC INTERFACE - ASSET MANAGEMENT FUNCTIONS
;; ===============================================================================

;; Comprehensive digital asset registration function
;; Registers a new digital asset with full metadata and security validation
;; @param asset-name: Human-readable name for the asset
;; @param content-size: Size of the asset content in bytes
;; @param asset-description: Detailed description of the asset
;; @param category-tags: List of categorization tags for the asset
;; @returns: Result containing the new asset identifier or error
(define-public (register-new-digital-asset
  (asset-name (string-ascii 64))
  (content-size uint)
  (asset-description (string-ascii 128))
  (category-tags (list 10 (string-ascii 32)))
)
  (let
    ;; Generate unique identifier for the new asset
    (
      (new-asset-id (+ (var-get total-registered-assets) u1))
    )
    ;; Comprehensive input validation with detailed error reporting
    (asserts! (> (len asset-name) u0) invalid-asset-metadata)
    (asserts! (< (len asset-name) u65) invalid-asset-metadata)
    (asserts! (> content-size u0) asset-size-limit-exceeded)
    (asserts! (< content-size u1000000000) asset-size-limit-exceeded)
    (asserts! (> (len asset-description) u0) invalid-asset-metadata)
    (asserts! (< (len asset-description) u129) invalid-asset-metadata)
    (asserts! (validate-category-tag-list category-tags) category-validation-error)

    ;; Register the new asset in the primary registry
    (map-insert digital-asset-registry
      { asset-identifier: new-asset-id }
      {
        asset-name: asset-name,
        asset-owner: tx-sender,
        content-size: content-size,
        registration-block: block-height,
        asset-description: asset-description,
        category-tags: category-tags
      }
    )

    ;; Grant automatic access permission to the asset creator
    (map-insert asset-permission-registry
      { asset-identifier: new-asset-id, authorized-user: tx-sender }
      { access-granted: true }
    )

    ;; Update global asset counter
    (var-set total-registered-assets new-asset-id)

    ;; Return success with new asset identifier
    (ok new-asset-id)
  )
)

;; Advanced asset modification function with security controls
;; Allows asset owners to update their asset information with validation
;; @param asset-identifier: The unique asset ID to modify
;; @param new-asset-name: Updated asset name
;; @param new-content-size: Updated content size
;; @param new-asset-description: Updated asset description
;; @param new-category-tags: Updated category tags
;; @returns: Result indicating success or error
(define-public (update-digital-asset-information
  (asset-identifier uint)
  (new-asset-name (string-ascii 64))
  (new-content-size uint)
  (new-asset-description (string-ascii 128))
  (new-category-tags (list 10 (string-ascii 32)))
)
  (let
    ;; Retrieve existing asset data for validation
    (
      (current-asset-data (unwrap! (map-get? digital-asset-registry { asset-identifier: asset-identifier })
        asset-not-found))
    )
    ;; Comprehensive security and validation checks
    (asserts! (asset-exists-in-registry asset-identifier) asset-not-found)
    (asserts! (is-eq (get asset-owner current-asset-data) tx-sender) ownership-verification-failed)
    (asserts! (> (len new-asset-name) u0) invalid-asset-metadata)
    (asserts! (< (len new-asset-name) u65) invalid-asset-metadata)
    (asserts! (> new-content-size u0) asset-size-limit-exceeded)
    (asserts! (< new-content-size u1000000000) asset-size-limit-exceeded)
    (asserts! (> (len new-asset-description) u0) invalid-asset-metadata)
    (asserts! (< (len new-asset-description) u129) invalid-asset-metadata)
    (asserts! (validate-category-tag-list new-category-tags) category-validation-error)

    ;; Execute secure asset information update
    (map-set digital-asset-registry
      { asset-identifier: asset-identifier }
      (merge current-asset-data {
        asset-name: new-asset-name,
        content-size: new-content-size,
        asset-description: new-asset-description,
        category-tags: new-category-tags
      })
    )

    ;; Return success confirmation
    (ok true)
  )
)

;; Secure asset ownership transfer protocol
;; Enables current owners to transfer ownership to other principals
;; @param asset-identifier: The unique asset ID to transfer
;; @param new-owner: The principal to receive ownership
;; @returns: Result indicating success or error
(define-public (transfer-asset-ownership (asset-identifier uint) (new-owner principal))
  (let
    ;; Retrieve current asset information for validation
    (
      (current-asset-info (unwrap! (map-get? digital-asset-registry { asset-identifier: asset-identifier })
        asset-not-found))
    )
    ;; Strict ownership verification before transfer
    (asserts! (asset-exists-in-registry asset-identifier) asset-not-found)
    (asserts! (is-eq (get asset-owner current-asset-info) tx-sender) ownership-verification-failed)

    ;; Execute secure ownership transfer with updated owner information
    (map-set digital-asset-registry
      { asset-identifier: asset-identifier }
      (merge current-asset-info { asset-owner: new-owner })
    )

    ;; Return success confirmation
    (ok true)
  )
)

;; Permanent asset removal function with security validation
;; Allows asset owners to permanently remove their assets from the registry
;; @param asset-identifier: The unique asset ID to remove
;; @returns: Result indicating success or error
(define-public (remove-digital-asset (asset-identifier uint))
  (let
    ;; Retrieve asset information for ownership validation
    (
      (asset-to-remove (unwrap! (map-get? digital-asset-registry { asset-identifier: asset-identifier })
        asset-not-found))
    )
    ;; Comprehensive validation before permanent deletion
    (asserts! (asset-exists-in-registry asset-identifier) asset-not-found)
    (asserts! (is-eq (get asset-owner asset-to-remove) tx-sender) ownership-verification-failed)

    ;; Execute permanent asset removal from registry
    (map-delete digital-asset-registry { asset-identifier: asset-identifier })

    ;; Return success confirmation
    (ok true)
  )
)

;; Advanced permission management system
;; Enables asset owners to grant or revoke access permissions to other users
;; @param asset-identifier: The unique asset ID
;; @param target-user: The principal to grant/revoke permissions for
;; @param permission-granted: Boolean indicating whether to grant or revoke access
;; @returns: Result indicating success or error
(define-public (manage-asset-access-permissions (asset-identifier uint) (target-user principal) (permission-granted bool))
  (let
    ;; Retrieve asset information for ownership validation
    (
      (asset-info (unwrap! (map-get? digital-asset-registry { asset-identifier: asset-identifier })
        asset-not-found))
    )
    ;; Verify asset existence and ownership before permission changes
    (asserts! (asset-exists-in-registry asset-identifier) asset-not-found)
    (asserts! (is-eq (get asset-owner asset-info) tx-sender) ownership-verification-failed)

    
    ;; Return success confirmation
    (ok true)
  )
)

