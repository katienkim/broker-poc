-- Replaces the in-memory tokenRegistry from
-- poc/apps/iam-broker/src/lib/token-registry.js. One row per issued token.
create table ia_tb_sso_token_h (
    jti             varchar(64)  primary key,
    format          varchar(16)  not null,
    uid             varchar(128) not null,
    role            varchar(64),
    brand           varchar(16),
    dealer_code     varchar(32),
    source_sys_id   varchar(64),
    target_sys_id   varchar(64) not null,
    token           text         not null,
    issued_at       timestamp    not null,
    expires_at      timestamp    not null,
    consumed        boolean      not null default false,
    consumed_at     timestamp
);

create index ix_token_history_token on ia_tb_sso_token_h (token);
create index ix_token_history_uid   on ia_tb_sso_token_h (uid);
create index ix_token_history_exp   on ia_tb_sso_token_h (expires_at);
