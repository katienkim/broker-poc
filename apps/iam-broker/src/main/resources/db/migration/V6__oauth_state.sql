-- Shared state table for SP-initiated flows (SAML RelayState, OIDC state code).
-- The opaque `state_code` is what travels through the IdP round-trip; on
-- callback we look up the row and recover `target_vendor` + `nonce` server-side.
-- This is the production pattern from
-- iam-broker-poc/idp-ui-feature-Admin_System_Configuration/backend (OAuthState).
create table ia_tb_oauth_state (
    state_code              varchar(128) primary key,
    nonce                   varchar(128),                 -- OIDC only; null for SAML
    flow                    varchar(16)  not null,        -- 'oidc' | 'saml'
    target_vendor           varchar(64),
    source_system           varchar(64),
    application_parameter   varchar(256),
    user_ip                 varchar(64),
    user_agent              varchar(512),
    used                    boolean      not null default false,
    created_at              timestamptz  not null default now(),
    expires_at              timestamptz  not null
);

create index idx_oauth_state_expires_at on ia_tb_oauth_state (expires_at);
