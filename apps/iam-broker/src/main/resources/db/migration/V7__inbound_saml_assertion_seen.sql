-- Replay defense for inbound SAML assertions. Spring Security SAML2 validates
-- signature + NotOnOrAfter + AudienceRestriction, but does NOT remember which
-- AssertionIDs it has already seen. An attacker who captures one valid signed
-- response can replay it within the NotOnOrAfter window without this table.
--
-- Rows are inserted at successful validation time keyed by AssertionID.
-- A second submission of the same AssertionID hits the primary-key conflict
-- and is rejected. Rows past `expires_at` (== NotOnOrAfter) are pruned by a
-- scheduled job.
create table ia_tb_inbound_saml_assertion_seen (
    assertion_id  varchar(256) primary key,
    issuer        varchar(256) not null,
    subject       varchar(256),
    seen_at       timestamptz  not null default now(),
    expires_at    timestamptz  not null
);

create index idx_inbound_saml_assertion_expires_at on ia_tb_inbound_saml_assertion_seen (expires_at);
