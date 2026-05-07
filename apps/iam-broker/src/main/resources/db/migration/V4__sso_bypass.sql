-- Direct port of poc/apps/iam-broker/src/lib/bypass-store.js.
create table ia_tb_sso_bypass (
    bypass_id      varchar(64)  primary key,
    user_id        varchar(128) not null,
    target_system  varchar(64)  not null,
    justification  varchar(512) not null,
    created_by     varchar(128) not null,
    created_at     timestamp    not null,
    expires_at     timestamp    not null
);

create index ix_bypass_lookup on ia_tb_sso_bypass (user_id, target_system, expires_at);
