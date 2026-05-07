-- Direct port of poc/apps/iam-broker/src/lib/revocation-store.js.
create table ia_tb_sso_revocation (
    id          varchar(160) primary key,    -- "token:<jti>" or "user:<uid>"
    type        varchar(8)   not null,
    subject     varchar(128) not null,
    reason      varchar(256) not null,
    revoked_at  timestamp    not null,
    expires_at  timestamp    not null
);

create index ix_revocation_subject on ia_tb_sso_revocation (subject);
