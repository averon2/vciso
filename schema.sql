-- =============================================================================
-- Virtual CISO Platform — PostgreSQL Schema
-- =============================================================================
-- Domain coverage:
--   * Identity & tenancy
--   * Application inventory (SentinelOne-fed)
--   * Threat intelligence (NVD, CISA KEV, FIRST EPSS)
--   * Scans & findings (per-CVE, per-host scope)
--   * Integrations (AWS, Azure, Cisco FW, SentinelOne, Jira, etc.)
--   * Course-of-action plans and execution runs
--   * Tickets (verification + manual) with acceptance criteria
--   * Email summaries and audit log
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- Extensions
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;        -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;          -- case-insensitive text
CREATE EXTENSION IF NOT EXISTS pg_trgm;         -- fuzzy product-name search

-- -----------------------------------------------------------------------------
-- Enums
-- -----------------------------------------------------------------------------
CREATE TYPE severity_label          AS ENUM ('CRITICAL','HIGH','MEDIUM','LOW','NONE');
CREATE TYPE cve_fix_status          AS ENUM ('YES','NO','CHECK_VENDOR');
CREATE TYPE version_affected_state  AS ENUM ('affected','not_affected','unknown');

CREATE TYPE integration_provider    AS ENUM (
    'aws','azure','cisco_firewall','sentinelone','jira',
    'intune','jamf','sccm','servicenow_cmdb'
);
CREATE TYPE integration_status      AS ENUM ('disconnected','connected','error','pending');

CREATE TYPE scan_kind                AS ENUM ('product','product_version','inventory_all');
CREATE TYPE scan_status              AS ENUM ('pending','running','complete','error','aborted');
CREATE TYPE scan_verdict             AS ENUM ('urgent','elevated','moderate','routine','clean');

CREATE TYPE coa_phase_kind           AS ENUM ('auto','verify','manual','email');
CREATE TYPE exec_status              AS ENUM ('pending','running','complete','aborted','failed');
CREATE TYPE exec_event_level         AS ENUM ('info','ok','warn','err');
CREATE TYPE exec_action_result       AS ENUM ('success','failed','skipped','deferred');

CREATE TYPE ticket_kind              AS ENUM ('verify','manual');
CREATE TYPE ticket_status            AS ENUM ('todo','in_progress','blocked','done','wont_do');
CREATE TYPE ticket_priority          AS ENUM ('highest','high','medium','low');

CREATE TYPE host_os                  AS ENUM ('windows','linux','macos','other','unknown');

-- -----------------------------------------------------------------------------
-- Shared trigger: updated_at
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- IDENTITY & TENANCY
-- =============================================================================
CREATE TABLE tenants (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text        NOT NULL,
    slug            citext      UNIQUE NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_tenants_updated BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE users (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           citext      UNIQUE NOT NULL,
    display_name    text,
    is_active       boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz
);
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE user_tenants (
    user_id         uuid        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role            text        NOT NULL DEFAULT 'member',      -- owner|admin|analyst|member|viewer
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX idx_user_tenants_tenant ON user_tenants (tenant_id);

-- =============================================================================
-- APPLICATION INVENTORY  (fed by SentinelOne agent)
-- =============================================================================
CREATE TABLE applications (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            text        NOT NULL,
    vendor          text,
    cpe_prefix      text,                       -- e.g. 'cpe:2.3:a:microsoft:word'
    notes           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE TRIGGER trg_applications_updated BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX idx_applications_tenant     ON applications (tenant_id);
CREATE INDEX idx_applications_name_trgm  ON applications USING gin (name gin_trgm_ops);

CREATE TABLE application_versions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id  uuid        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         text        NOT NULL,
    released_at     date,
    is_current      boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);
CREATE INDEX idx_application_versions_app ON application_versions (application_id);

CREATE TABLE hosts (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    system_name             text        NOT NULL,               -- WIN-DESK-0142
    dns_name                text,                                -- win-desk-0142.corp.local
    os                      host_os     NOT NULL DEFAULT 'unknown',
    os_version              text,
    ip_address              inet,
    sentinelone_agent_id    text        UNIQUE,
    tags                    text[]      NOT NULL DEFAULT '{}',
    is_active               boolean     NOT NULL DEFAULT true,
    first_seen_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, system_name)
);
CREATE TRIGGER trg_hosts_updated BEFORE UPDATE ON hosts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX idx_hosts_tenant    ON hosts (tenant_id);
CREATE INDEX idx_hosts_dns       ON hosts (dns_name);
CREATE INDEX idx_hosts_last_seen ON hosts (last_seen_at DESC);
CREATE INDEX idx_hosts_tags_gin  ON hosts USING gin (tags);

-- Which hosts run which application-version (the live S1 inventory join)
CREATE TABLE host_applications (
    host_id         uuid        NOT NULL REFERENCES hosts(id)                 ON DELETE CASCADE,
    app_version_id  uuid        NOT NULL REFERENCES application_versions(id) ON DELETE CASCADE,
    install_path    text,
    installed_at    timestamptz,
    reported_at     timestamptz NOT NULL DEFAULT now(),
    source          integration_provider NOT NULL DEFAULT 'sentinelone',
    PRIMARY KEY (host_id, app_version_id)
);
CREATE INDEX idx_host_apps_version ON host_applications (app_version_id);
CREATE INDEX idx_host_apps_host    ON host_applications (host_id);

CREATE TABLE sentinelone_sync_log (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    started_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    hosts_reported  int,
    apps_reported   int,
    status          text        NOT NULL DEFAULT 'running',     -- running|ok|error
    error_message   text
);
CREATE INDEX idx_s1_sync_tenant_started ON sentinelone_sync_log (tenant_id, started_at DESC);

-- =============================================================================
-- THREAT INTELLIGENCE  (NVD, CISA KEV, FIRST EPSS)
-- =============================================================================
CREATE TABLE cves (
    id                      text        PRIMARY KEY,              -- 'CVE-2024-12345'
    description             text        NOT NULL,
    published_at            timestamptz,
    last_modified_at        timestamptz,
    vuln_status             text,

    cvss_v31_score          numeric(3,1) CHECK (cvss_v31_score IS NULL OR (cvss_v31_score BETWEEN 0 AND 10)),
    cvss_v31_vector         text,
    cvss_v30_score          numeric(3,1) CHECK (cvss_v30_score IS NULL OR (cvss_v30_score BETWEEN 0 AND 10)),
    cvss_v2_score           numeric(3,1) CHECK (cvss_v2_score   IS NULL OR (cvss_v2_score   BETWEEN 0 AND 10)),
    cvss_score              numeric(3,1) GENERATED ALWAYS AS
                            (COALESCE(cvss_v31_score, cvss_v30_score, cvss_v2_score)) STORED,
    cvss_severity           severity_label,

    cwe                     text[]      NOT NULL DEFAULT '{}',
    has_fix                 boolean,
    patch_url               text,
    affected_versions_text  text,                                 -- denormalized display string

    fetched_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_cves_updated BEFORE UPDATE ON cves
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX idx_cves_score      ON cves (cvss_score DESC NULLS LAST);
CREATE INDEX idx_cves_published  ON cves (published_at DESC);
CREATE INDEX idx_cves_severity   ON cves (cvss_severity);
CREATE INDEX idx_cves_desc_trgm  ON cves USING gin (description gin_trgm_ops);

CREATE TABLE cve_references (
    id          bigserial   PRIMARY KEY,
    cve_id      text        NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    url         text        NOT NULL,
    source      text,
    tags        text[]      NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_cve_refs_cve ON cve_references (cve_id);

CREATE TABLE cve_cpes (
    id                      bigserial   PRIMARY KEY,
    cve_id                  text        NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    cpe23                   text        NOT NULL,
    vendor                  text,
    product                 text,
    version_start_including text,
    version_start_excluding text,
    version_end_including   text,
    version_end_excluding   text,
    vulnerable              boolean     NOT NULL DEFAULT true
);
CREATE INDEX idx_cve_cpes_cve      ON cve_cpes (cve_id);
CREATE INDEX idx_cve_cpes_product  ON cve_cpes (vendor, product);

CREATE TABLE kev_entries (
    cve_id              text        PRIMARY KEY REFERENCES cves(id) ON DELETE CASCADE,
    vendor_project      text,
    product             text,
    vulnerability_name  text,
    date_added          date,
    due_date            date,
    required_action     text,
    known_ransomware    boolean,
    notes               text,
    fetched_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_kev_due_date ON kev_entries (due_date);

-- EPSS updates daily; keep history for trending.
CREATE TABLE epss_scores (
    cve_id      text        NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    scored_on   date        NOT NULL,
    score       numeric(6,5) NOT NULL CHECK (score BETWEEN 0 AND 1),
    percentile  numeric(6,5) CHECK (percentile IS NULL OR (percentile BETWEEN 0 AND 1)),
    fetched_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, scored_on)
);
CREATE INDEX idx_epss_latest ON epss_scores (cve_id, scored_on DESC);

CREATE TABLE threat_source_sync_log (
    id                  bigserial   PRIMARY KEY,
    source              text        NOT NULL,               -- 'nvd'|'kev'|'epss'
    started_at          timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz,
    records_processed   int,
    status              text        NOT NULL DEFAULT 'running',
    error_message       text
);
CREATE INDEX idx_threat_sync_source_started ON threat_source_sync_log (source, started_at DESC);

-- =============================================================================
-- SCANS & FINDINGS
-- =============================================================================
CREATE TABLE scans (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    initiated_by_user_id    uuid        REFERENCES users(id) ON DELETE SET NULL,
    kind                    scan_kind   NOT NULL,
    product_query           text,                                -- raw query term (e.g. 'microsoft word')
    version_query           text,
    application_id          uuid        REFERENCES applications(id) ON DELETE SET NULL,
    application_version_id  uuid        REFERENCES application_versions(id) ON DELETE SET NULL,
    status                  scan_status NOT NULL DEFAULT 'pending',
    verdict                 scan_verdict,
    narrative               text,
    total_cves              int         NOT NULL DEFAULT 0,
    kev_count               int         NOT NULL DEFAULT 0,
    critical_count          int         NOT NULL DEFAULT 0,
    high_epss_count         int         NOT NULL DEFAULT 0,
    has_fix_count           int         NOT NULL DEFAULT 0,
    affecting_hosts_count   int         NOT NULL DEFAULT 0,
    started_at              timestamptz NOT NULL DEFAULT now(),
    completed_at            timestamptz,
    error_message           text
);
CREATE INDEX idx_scans_tenant_started ON scans (tenant_id, started_at DESC);
CREATE INDEX idx_scans_kind           ON scans (kind);

CREATE TABLE scan_findings (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             uuid        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id              text        NOT NULL REFERENCES cves(id) ON DELETE RESTRICT,
    severity_snapshot   severity_label,
    cvss_snapshot       numeric(3,1),
    epss_snapshot       numeric(6,5),
    is_kev              boolean     NOT NULL DEFAULT false,
    fix_snapshot        cve_fix_status,
    priority_score      numeric(6,2),                            -- KEV*10 + EPSS*5 + CVSS*3
    version_affected    version_affected_state NOT NULL DEFAULT 'unknown',
    UNIQUE (scan_id, cve_id)
);
CREATE INDEX idx_scan_findings_scan     ON scan_findings (scan_id);
CREATE INDEX idx_scan_findings_cve      ON scan_findings (cve_id);
CREATE INDEX idx_scan_findings_priority ON scan_findings (scan_id, priority_score DESC);

-- Apps that contributed this finding (relevant mostly for inventory-wide scans)
CREATE TABLE scan_finding_applications (
    finding_id      uuid NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
    application_id  uuid NOT NULL REFERENCES applications(id)  ON DELETE CASCADE,
    PRIMARY KEY (finding_id, application_id)
);
CREATE INDEX idx_sfa_app ON scan_finding_applications (application_id);

-- Exact host scope per finding, derived from the SentinelOne inventory
CREATE TABLE scan_finding_hosts (
    finding_id      uuid NOT NULL REFERENCES scan_findings(id) ON DELETE CASCADE,
    host_id         uuid NOT NULL REFERENCES hosts(id)          ON DELETE CASCADE,
    app_version_id  uuid REFERENCES application_versions(id)    ON DELETE SET NULL,
    PRIMARY KEY (finding_id, host_id)
);
CREATE INDEX idx_sfh_host ON scan_finding_hosts (host_id);

-- =============================================================================
-- INTEGRATIONS
-- =============================================================================
CREATE TABLE integrations (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider            integration_provider NOT NULL,
    display_name        text,
    status              integration_status NOT NULL DEFAULT 'disconnected',
    config              jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- non-secret (region, workspace URL, project key)
    connected_at        timestamptz,
    last_checked_at     timestamptz,
    error_message       text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider)
);
CREATE TRIGGER trg_integrations_updated BEFORE UPDATE ON integrations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX idx_integrations_tenant ON integrations (tenant_id);

-- Secrets live in a dedicated table so main integrations row can be selected safely.
CREATE TABLE integration_credentials (
    integration_id      uuid        PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE,
    encrypted_payload   bytea       NOT NULL,                       -- KMS/DEK-wrapped blob
    key_version         int         NOT NULL DEFAULT 1,
    rotated_at          timestamptz NOT NULL DEFAULT now()
);

-- Catalog of what each provider can do (populated once, referenced by CoA actions).
CREATE TABLE integration_capabilities (
    id              bigserial   PRIMARY KEY,
    provider        integration_provider NOT NULL,
    capability_key  text        NOT NULL,           -- 'aws.ssm.patch'
    label           text        NOT NULL,           -- 'Deploy via SSM Patch Manager'
    description     text,
    UNIQUE (provider, capability_key)
);

-- =============================================================================
-- COURSE-OF-ACTION PLANS  (recommended remediation plan per scan)
-- =============================================================================
CREATE TABLE coa_plans (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         uuid        NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    product_label   text        NOT NULL,
    auto_count      int         NOT NULL DEFAULT 0,
    verify_count    int         NOT NULL DEFAULT 0,
    manual_count    int         NOT NULL DEFAULT 0,
    email_enabled   boolean     NOT NULL DEFAULT true,
    phase_toggles   jsonb       NOT NULL DEFAULT '{"auto":true,"verify":true,"manual":true,"email":true}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- A single recommended automated action against a specific finding.
CREATE TABLE coa_auto_actions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id         uuid        NOT NULL REFERENCES coa_plans(id)        ON DELETE CASCADE,
    finding_id      uuid        NOT NULL REFERENCES scan_findings(id)    ON DELETE CASCADE,
    provider        integration_provider NOT NULL,
    capability_key  text        NOT NULL,
    action_label    text        NOT NULL,
    sequence_order  int         NOT NULL DEFAULT 0
);
CREATE INDEX idx_coa_actions_plan    ON coa_auto_actions (plan_id);
CREATE INDEX idx_coa_actions_finding ON coa_auto_actions (finding_id);

-- =============================================================================
-- EXECUTION RUNS  (what actually happened when the user approved the plan)
-- =============================================================================
CREATE TABLE execution_runs (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id                 uuid        NOT NULL REFERENCES coa_plans(id) ON DELETE CASCADE,
    approved_by_user_id     uuid        REFERENCES users(id) ON DELETE SET NULL,
    approved_at             timestamptz NOT NULL DEFAULT now(),
    started_at              timestamptz,
    completed_at            timestamptz,
    status                  exec_status NOT NULL DEFAULT 'pending',
    phase_toggles_snapshot  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    auto_succeeded          int         NOT NULL DEFAULT 0,
    auto_failed             int         NOT NULL DEFAULT 0,
    verify_created          int         NOT NULL DEFAULT 0,
    manual_created          int         NOT NULL DEFAULT 0,
    email_sent              boolean     NOT NULL DEFAULT false,
    aborted_reason          text
);
CREATE INDEX idx_exec_runs_plan   ON execution_runs (plan_id);
CREATE INDEX idx_exec_runs_status ON execution_runs (status);

-- Streaming log (each "→ / ✓ / !" line in the UI overlay)
CREATE TABLE execution_events (
    id              bigserial   PRIMARY KEY,
    run_id          uuid        NOT NULL REFERENCES execution_runs(id) ON DELETE CASCADE,
    phase           coa_phase_kind NOT NULL,
    level           exec_event_level NOT NULL DEFAULT 'info',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    finding_id      uuid        REFERENCES scan_findings(id) ON DELETE SET NULL,
    host_id         uuid        REFERENCES hosts(id)          ON DELETE SET NULL,
    provider        integration_provider,
    message         text        NOT NULL,
    details         jsonb
);
CREATE INDEX idx_exec_events_run      ON execution_events (run_id, occurred_at);
CREATE INDEX idx_exec_events_finding  ON execution_events (finding_id);
CREATE INDEX idx_exec_events_host     ON execution_events (host_id);

-- Per-host result of each automated action (one row per host × action attempt)
CREATE TABLE execution_action_results (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          uuid        NOT NULL REFERENCES execution_runs(id)   ON DELETE CASCADE,
    auto_action_id  uuid        NOT NULL REFERENCES coa_auto_actions(id) ON DELETE CASCADE,
    host_id         uuid        REFERENCES hosts(id) ON DELETE SET NULL,
    status          exec_action_result NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    provider_ref    text,                                   -- e.g. SSM command id, Azure run id
    error_message   text
);
CREATE INDEX idx_exec_action_results_run    ON execution_action_results (run_id);
CREATE INDEX idx_exec_action_results_action ON execution_action_results (auto_action_id);

-- =============================================================================
-- TICKETS  (SEC-V… verification + SEC-M… manual-fix)
-- =============================================================================
CREATE TABLE tickets (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_id                 uuid        REFERENCES scans(id)           ON DELETE SET NULL,
    run_id                  uuid        REFERENCES execution_runs(id)  ON DELETE SET NULL,
    finding_id              uuid        REFERENCES scan_findings(id)   ON DELETE SET NULL,
    cve_id                  text        REFERENCES cves(id)            ON DELETE SET NULL,
    kind                    ticket_kind NOT NULL,
    internal_key            text        UNIQUE,                  -- 'SEC-V1000' / 'SEC-M2000'
    external_jira_key       text,                                -- Jira-assigned key once created
    external_jira_url       text,
    summary                 text        NOT NULL,
    description_markdown    text,
    priority                ticket_priority NOT NULL DEFAULT 'medium',
    status                  ticket_status   NOT NULL DEFAULT 'todo',
    assignee                text,
    reporter                text,
    story_points            int,
    due_date                date,
    labels                  text[]      NOT NULL DEFAULT '{}',
    components              text[]      NOT NULL DEFAULT '{}',
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    closed_at               timestamptz
);
CREATE TRIGGER trg_tickets_updated BEFORE UPDATE ON tickets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX idx_tickets_tenant_status ON tickets (tenant_id, status);
CREATE INDEX idx_tickets_scan    ON tickets (scan_id);
CREATE INDEX idx_tickets_finding ON tickets (finding_id);
CREATE INDEX idx_tickets_cve     ON tickets (cve_id);
CREATE INDEX idx_tickets_kind    ON tickets (kind);
CREATE INDEX idx_tickets_labels  ON tickets USING gin (labels);

-- Exact host scope per ticket (renders the "Affected hosts" section)
CREATE TABLE ticket_hosts (
    ticket_id   uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    host_id     uuid NOT NULL REFERENCES hosts(id)   ON DELETE CASCADE,
    PRIMARY KEY (ticket_id, host_id)
);
CREATE INDEX idx_ticket_hosts_host ON ticket_hosts (host_id);

-- What the engineer must verify / measure, with its verification command if any.
CREATE TABLE ticket_acceptance_criteria (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id               uuid        NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    sequence_order          int         NOT NULL DEFAULT 0,
    title                   text        NOT NULL,
    detail_markdown         text,
    verification_command    text,
    is_done                 boolean     NOT NULL DEFAULT false,
    done_at                 timestamptz,
    done_by_user_id         uuid        REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_tac_ticket ON ticket_acceptance_criteria (ticket_id, sequence_order);

-- Remediation steps for manual tickets (staged rollout, mitigations, etc.)
CREATE TABLE ticket_remediation_steps (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id           uuid        NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    sequence_order      int         NOT NULL DEFAULT 0,
    title               text        NOT NULL,
    detail_markdown     text,
    is_done             boolean     NOT NULL DEFAULT false,
    done_at             timestamptz
);
CREATE INDEX idx_trs_ticket ON ticket_remediation_steps (ticket_id, sequence_order);

-- Ties verification tickets back to the auto-action(s) that triggered them.
CREATE TABLE ticket_linked_actions (
    ticket_id       uuid NOT NULL REFERENCES tickets(id)          ON DELETE CASCADE,
    auto_action_id  uuid NOT NULL REFERENCES coa_auto_actions(id) ON DELETE CASCADE,
    PRIMARY KEY (ticket_id, auto_action_id)
);
CREATE INDEX idx_tla_action ON ticket_linked_actions (auto_action_id);

-- =============================================================================
-- EXECUTIVE EMAIL SUMMARIES
-- =============================================================================
CREATE TABLE email_summaries (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id              uuid        NOT NULL REFERENCES execution_runs(id) ON DELETE CASCADE,
    subject             text        NOT NULL,
    body_markdown       text        NOT NULL,
    body_text           text,
    sent_at             timestamptz,
    provider            text,                                   -- 'ses'|'sendgrid'|'smtp'
    provider_message_id text,
    error_message       text
);
CREATE INDEX idx_email_summaries_run ON email_summaries (run_id);

CREATE TABLE email_recipients (
    id          bigserial   PRIMARY KEY,
    email_id    uuid        NOT NULL REFERENCES email_summaries(id) ON DELETE CASCADE,
    address     citext      NOT NULL,
    role        text        NOT NULL DEFAULT 'to'               -- 'to'|'cc'|'bcc'
);
CREATE INDEX idx_email_recipients_email ON email_recipients (email_id);

-- =============================================================================
-- AUDIT LOG
-- =============================================================================
CREATE TABLE audit_log (
    id              bigserial   PRIMARY KEY,
    tenant_id       uuid        REFERENCES tenants(id) ON DELETE SET NULL,
    user_id         uuid        REFERENCES users(id)   ON DELETE SET NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    action          text        NOT NULL,                       -- 'scan.start','coa.approve','integration.connect',...
    entity_type     text,                                       -- 'scan','ticket','integration',...
    entity_id       text,
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ip_address      inet,
    user_agent      text
);
CREATE INDEX idx_audit_tenant_time ON audit_log (tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_entity      ON audit_log (entity_type, entity_id);
CREATE INDEX idx_audit_action_time ON audit_log (action, occurred_at DESC);

-- =============================================================================
-- CONVENIENCE VIEWS
-- =============================================================================

-- Latest EPSS score per CVE.
CREATE VIEW cve_latest_epss AS
SELECT DISTINCT ON (cve_id)
    cve_id, score, percentile, scored_on, fetched_at
FROM epss_scores
ORDER BY cve_id, scored_on DESC;

-- Host × CVE exposure via completed scans (who has what, derived from findings).
CREATE VIEW host_cve_exposure AS
SELECT
    sfh.host_id,
    sf.cve_id,
    sf.severity_snapshot,
    sf.priority_score,
    sf.is_kev,
    sf.fix_snapshot,
    s.tenant_id,
    s.id          AS scan_id,
    s.started_at  AS scan_started_at
FROM scan_finding_hosts sfh
JOIN scan_findings      sf ON sf.id = sfh.finding_id
JOIN scans              s  ON s.id  = sf.scan_id;

-- Total hosts per application (rolls up versions).
CREATE VIEW application_host_counts AS
SELECT
    a.id                    AS application_id,
    a.tenant_id,
    a.name,
    COUNT(DISTINCT ha.host_id) AS host_count,
    COUNT(DISTINCT av.id)      AS version_count
FROM applications a
LEFT JOIN application_versions av ON av.application_id = a.id
LEFT JOIN host_applications    ha ON ha.app_version_id = av.id
GROUP BY a.id, a.tenant_id, a.name;

-- Open tickets summary per tenant.
CREATE VIEW open_ticket_summary AS
SELECT
    tenant_id,
    kind,
    priority,
    COUNT(*) AS open_count
FROM tickets
WHERE status NOT IN ('done','wont_do')
GROUP BY tenant_id, kind, priority;

-- =============================================================================
-- SEED: integration capability catalog (reflects what the UI offers today)
-- =============================================================================
INSERT INTO integration_capabilities (provider, capability_key, label, description) VALUES
    ('aws',            'aws.ssm.patch',               'SSM Patch Manager deploy',         'Patch EC2 instances via AWS Systems Manager Patch Manager.'),
    ('aws',            'aws.ssm.patch.emergency',     'Emergency SSM patch push',         'Out-of-band SSM run on KEV findings.'),
    ('aws',            'aws.sg.tighten',              'Tighten Security Groups',          'Remove broad inbound rules on affected instances.'),
    ('aws',            'aws.inspector.rescan',        'Trigger Inspector re-scan',        'Re-scan affected instances after remediation.'),
    ('azure',          'azure.updates.schedule',      'Update Manager schedule',          'Queue patching via Azure Update Manager.'),
    ('azure',          'azure.updates.emergency',     'Emergency Update Manager run',     'Immediate Update Manager deployment.'),
    ('azure',          'azure.nsg.block',             'NSG inbound block',                'Push NSG rule changes to restrict traffic.'),
    ('azure',          'azure.defender.remediate',    'Defender for Cloud remediation',   'Apply Defender-suggested remediation.'),
    ('cisco_firewall', 'cisco.block.ioc',             'Block IOCs at perimeter',          'Push IOC blocks to Firepower / ASA.'),
    ('cisco_firewall', 'cisco.acl.restrict',          'Restrict inbound ACL',             'Tighten ACLs for affected hosts.'),
    ('cisco_firewall', 'cisco.ips.signature',         'Enable IPS signature',             'Turn on signature-based IPS protections.'),
    ('sentinelone',    's1.inventory.sync',           'Sync host & software inventory',   'Pull installed applications and host identity.'),
    ('jira',           'jira.issue.create',           'Create Jira issue',                'Create issues via Jira REST API.')
ON CONFLICT DO NOTHING;

COMMIT;
