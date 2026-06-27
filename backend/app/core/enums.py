"""Shared domain enumerations (dependency-free).

These live in ``app.core`` so any layer — core, models, schemas, services — can use
them without importing the ORM. ``app.models.enums`` re-exports them for ergonomic
``from app.models.enums import ...`` access in model definitions.
"""

from __future__ import annotations

from enum import StrEnum


class FileCategory(StrEnum):
    video = "video"
    audio = "audio"
    image = "image"
    document = "document"
    pdf = "pdf"
    json = "json"
    csv = "csv"
    backup = "backup"
    log = "log"
    evidence = "evidence"
    archive = "archive"
    other = "other"


class FileStatus(StrEnum):
    uploaded = "uploaded"        # received, not yet encrypted
    encrypted = "encrypted"      # ciphertext written to vault
    available = "available"      # encrypted + integrity recorded, ready
    quarantined = "quarantined"  # integrity failure / suspected tamper
    deleted = "deleted"          # crypto-shredded (key destroyed)


class KeyType(StrEnum):
    data = "data"          # per-file Data Encryption Key (DEK)
    field = "field"        # database field encryption key
    master_ref = "master"  # reference to a KMS master key (KEK)


class KeyStatus(StrEnum):
    active = "active"
    rotated = "rotated"
    revoked = "revoked"
    expired = "expired"
    compromised = "compromised"
    destroyed = "destroyed"  # crypto-shredded


class RotationType(StrEnum):
    dek_rotation = "dek_rotation"
    master_key_rotation = "master_key_rotation"
    field_key_rotation = "field_key_rotation"


class AuditEventType(StrEnum):
    login = "login"
    logout = "logout"
    login_failed = "login_failed"
    upload = "upload"
    download = "download"
    encrypt = "encrypt"
    decrypt = "decrypt"
    decrypt_failed = "decrypt_failed"
    delete = "delete"
    restore = "restore"
    integrity_check = "integrity_check"
    integrity_violation = "integrity_violation"
    key_generated = "key_generated"
    key_rotation = "key_rotation"
    key_revoked = "key_revoked"
    failed_access = "failed_access"
    access_denied = "access_denied"
    password_change = "password_change"
    role_change = "role_change"
    report_generated = "report_generated"
    config_change = "config_change"
    # Security Monitoring Platform events
    asset_created = "asset_created"
    asset_updated = "asset_updated"
    asset_deleted = "asset_deleted"
    scan_started = "scan_started"
    scan_completed = "scan_completed"
    vulnerability_detected = "vulnerability_detected"
    alert_triggered = "alert_triggered"
    incident_created = "incident_created"
    incident_updated = "incident_updated"


class AuditOutcome(StrEnum):
    success = "success"
    failure = "failure"
    denied = "denied"


class IntegrityTarget(StrEnum):
    plaintext = "plaintext"    # hash of original content
    ciphertext = "ciphertext"  # hash of stored encrypted blob (at-rest tamper)


class IntegrityResult(StrEnum):
    passed = "passed"
    failed = "failed"
    error = "error"


class AlertType(StrEnum):
    integrity_violation = "integrity_violation"
    failed_decryption = "failed_decryption"
    brute_force = "brute_force"
    unauthorized_access = "unauthorized_access"
    key_compromise = "key_compromise"
    tamper_detected = "tamper_detected"
    anomaly = "anomaly"
    policy_violation = "policy_violation"
    vulnerability = "vulnerability"
    new_asset = "new_asset"
    risky_port = "risky_port"


class AlertSeverity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


class ComplianceFramework(StrEnum):
    owasp_asvs = "owasp_asvs"
    nist_csf = "nist_csf"
    nist_crypto = "nist_crypto"
    iso_27001 = "iso_27001"


class ReportStatus(StrEnum):
    draft = "draft"
    final = "final"


# ════════════════════════════════════════════════════════════════
#  Security Monitoring Platform (SMP) enums
# ════════════════════════════════════════════════════════════════
class AssetType(StrEnum):
    host = "host"
    server = "server"
    workstation = "workstation"
    network_device = "network_device"
    router = "router"
    switch = "switch"
    firewall = "firewall"
    service = "service"
    application = "application"
    database = "database"
    iot = "iot"
    cloud_resource = "cloud_resource"
    other = "other"


class AssetCriticality(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AssetEnvironment(StrEnum):
    production = "production"
    staging = "staging"
    development = "development"
    test = "test"
    unknown = "unknown"


class AssetStatus(StrEnum):
    active = "active"
    inactive = "inactive"
    decommissioned = "decommissioned"
    quarantined = "quarantined"


class DiscoverySource(StrEnum):
    manual = "manual"
    network_discovery = "network_discovery"
    import_ = "import"


class ScanStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class VulnSeverity(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class VulnStatus(StrEnum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    remediated = "remediated"
    accepted_risk = "accepted_risk"


class IncidentStatus(StrEnum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class IncidentSeverity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertRuleType(StrEnum):
    vuln_severity = "vuln_severity"          # finding severity >= threshold
    critical_asset_vuln = "critical_asset_vuln"  # any vuln on a critical asset
    new_host = "new_host"                    # discovery found an unknown host
    open_port = "open_port"                  # a watched/risky port is open
    integrity_violation = "integrity_violation"
    brute_force = "brute_force"


# ════════════════════════════════════════════════════════════════
#  Unified Security Platform (USP) — Multi-tenancy & physical estate
# ════════════════════════════════════════════════════════════════
class OrgStatus(StrEnum):
    trial = "trial"
    active = "active"
    suspended = "suspended"
    cancelled = "cancelled"


class SubscriptionPlan(StrEnum):
    trial = "trial"
    starter = "starter"
    professional = "professional"
    enterprise = "enterprise"


class SubscriptionStatus(StrEnum):
    trialing = "trialing"
    active = "active"
    past_due = "past_due"
    suspended = "suspended"
    cancelled = "cancelled"


class SiteType(StrEnum):
    office = "office"
    warehouse = "warehouse"
    retail = "retail"
    datacenter = "datacenter"
    residential = "residential"
    industrial = "industrial"
    campus = "campus"
    hospital = "hospital"
    bank = "bank"
    other = "other"


class SiteStatus(StrEnum):
    active = "active"
    inactive = "inactive"
    under_construction = "under_construction"
    decommissioned = "decommissioned"


class ZoneType(StrEnum):
    general = "general"
    restricted = "restricted"
    perimeter = "perimeter"
    entrance = "entrance"
    parking = "parking"
    server_room = "server_room"
    emergency_exit = "emergency_exit"
    high_security = "high_security"
    other = "other"


class CheckpointType(StrEnum):
    qr = "qr"
    nfc = "nfc"
    gps = "gps"
    manual = "manual"


# ── Physical security: cameras ──────────────────────────────────
class CameraStatus(StrEnum):
    online = "online"
    offline = "offline"
    degraded = "degraded"
    maintenance = "maintenance"
    disabled = "disabled"


class StreamQuality(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


# ── Physical security: guards & patrols ─────────────────────────
class GuardStatus(StrEnum):
    on_duty = "on_duty"
    off_duty = "off_duty"
    on_leave = "on_leave"
    suspended = "suspended"


class PatrolStatus(StrEnum):
    scheduled = "scheduled"
    in_progress = "in_progress"
    completed = "completed"
    missed = "missed"
    cancelled = "cancelled"


# ── Physical security: visitors & contractors ───────────────────
class VisitorStatus(StrEnum):
    pre_registered = "pre_registered"
    pending_approval = "pending_approval"
    approved = "approved"
    checked_in = "checked_in"
    checked_out = "checked_out"
    denied = "denied"
    blacklisted = "blacklisted"


class ContractorStatus(StrEnum):
    pending = "pending"
    active = "active"
    expired = "expired"
    suspended = "suspended"


# ── Physical security: access control ───────────────────────────
class AccessPointType(StrEnum):
    door = "door"
    turnstile = "turnstile"
    gate = "gate"
    barrier = "barrier"
    elevator = "elevator"


class AccessMethod(StrEnum):
    rfid = "rfid"
    smart_card = "smart_card"
    qr = "qr"
    biometric = "biometric"
    fingerprint = "fingerprint"
    face = "face"
    pin = "pin"


class AccessDecision(StrEnum):
    granted = "granted"
    denied = "denied"


# ── Physical security: vehicles & ANPR ──────────────────────────
class VehicleStatus(StrEnum):
    active = "active"
    watchlisted = "watchlisted"
    blacklisted = "blacklisted"
    flagged = "flagged"


class VehicleDirection(StrEnum):
    entry = "entry"
    exit = "exit"


# ════════════════════════════════════════════════════════════════
#  AI detection & threat intelligence
# ════════════════════════════════════════════════════════════════
class DetectionType(StrEnum):
    # People
    person = "person"
    multiple_persons = "multiple_persons"
    unknown_person = "unknown_person"
    face_match = "face_match"
    # Vehicles
    vehicle = "vehicle"
    # Threats / objects
    weapon = "weapon"
    suspicious_object = "suspicious_object"
    abandoned_object = "abandoned_object"
    removed_object = "removed_object"
    # Environmental
    fire = "fire"
    smoke = "smoke"
    flood = "flood"
    # Behavioural
    loitering = "loitering"
    running = "running"
    crowd = "crowd"
    intrusion = "intrusion"
    perimeter_breach = "perimeter_breach"
    tailgating = "tailgating"


class DetectionStatus(StrEnum):
    new = "new"
    reviewing = "reviewing"
    confirmed = "confirmed"
    dismissed = "dismissed"


class ThreatLevel(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ThreatStatus(StrEnum):
    active = "active"
    monitoring = "monitoring"
    mitigated = "mitigated"
    escalated = "escalated"
    closed = "closed"


# ════════════════════════════════════════════════════════════════
#  SecOps: notifications, emergency response, evidence
# ════════════════════════════════════════════════════════════════
class NotificationChannel(StrEnum):
    email = "email"
    sms = "sms"
    whatsapp = "whatsapp"
    push = "push"
    webhook = "webhook"


class NotificationStatus(StrEnum):
    queued = "queued"
    sent = "sent"
    delivered = "delivered"
    failed = "failed"


class EmergencyType(StrEnum):
    panic = "panic"
    lockdown = "lockdown"
    evacuation = "evacuation"
    fire = "fire"
    medical = "medical"
    police = "police"
    broadcast = "broadcast"


class EmergencyStatus(StrEnum):
    active = "active"
    acknowledged = "acknowledged"
    resolved = "resolved"


class EvidenceType(StrEnum):
    video = "video"
    image = "image"
    document = "document"
    audio = "audio"
    physical = "physical"
    other = "other"


class EvidenceStatus(StrEnum):
    collected = "collected"
    sealed = "sealed"
    released = "released"
    destroyed = "destroyed"


class CustodyAction(StrEnum):
    collected = "collected"
    accessed = "accessed"
    transferred = "transferred"
    sealed = "sealed"
    released = "released"
    destroyed = "destroyed"


# ════════════════════════════════════════════════════════════════
#  Cybersecurity monitoring (the cyber differentiator)
# ════════════════════════════════════════════════════════════════
class CyberEventType(StrEnum):
    failed_login = "failed_login"
    brute_force = "brute_force"
    suspicious_login = "suspicious_login"
    impossible_travel = "impossible_travel"
    new_device = "new_device"
    privilege_escalation = "privilege_escalation"
    api_abuse = "api_abuse"
    account_lockout = "account_lockout"
    session_anomaly = "session_anomaly"


class CyberEventStatus(StrEnum):
    new = "new"
    reviewing = "reviewing"
    resolved = "resolved"
    false_positive = "false_positive"


# ════════════════════════════════════════════════════════════════
#  Communication & workflow automation
# ════════════════════════════════════════════════════════════════
class AnnouncementAudience(StrEnum):
    all = "all"
    guards = "guards"
    officers = "officers"
    admins = "admins"


class AutomationTrigger(StrEnum):
    detection = "detection"
    threat = "threat"
    incident = "incident"
    cyber_event = "cyber_event"
    access_denied = "access_denied"
    manual = "manual"


class AutomationAction(StrEnum):
    notify = "notify"
    create_incident = "create_incident"
    escalate = "escalate"
    log = "log"


# ════════════════════════════════════════════════════════════════
#  SaaS: billing, system administration, integrations
# ════════════════════════════════════════════════════════════════
class InvoiceStatus(StrEnum):
    draft = "draft"
    sent = "sent"
    paid = "paid"
    overdue = "overdue"
    void = "void"


class PaymentStatus(StrEnum):
    pending = "pending"
    completed = "completed"
    failed = "failed"
    refunded = "refunded"


class PaymentMethod(StrEnum):
    card = "card"
    bank_transfer = "bank_transfer"
    mpesa = "mpesa"
    cash = "cash"
    other = "other"


class BackupStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class SettingScope(StrEnum):
    global_ = "global"
    tenant = "tenant"


class IntegrationKind(StrEnum):
    slack = "slack"
    teams = "teams"
    email_smtp = "email_smtp"
    sms_gateway = "sms_gateway"
    siem = "siem"
    webhook = "webhook"
    vms = "vms"
    anpr = "anpr"
    access_control = "access_control"


class IntegrationStatus(StrEnum):
    active = "active"
    inactive = "inactive"
    error = "error"
