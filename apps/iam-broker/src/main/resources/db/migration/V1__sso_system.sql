-- Vendor catalog. One row per target system.
-- Mirrors poc/apps/iam-broker/src/lib/target-systems.js exactly.
create table ia_tb_sso_sys_mngmt_m (
    source_sys_id          varchar(64)  primary key,
    source_sys_name        varchar(128) not null,
    source_sys_type        varchar(16)  not null,    -- igtk | saml | aes256 | rc4 | wpc-otp
    direct_reurl_d         varchar(512) not null,
    direct_reurl_m         varchar(512),
    is_source_sys_active   integer      not null default 1,
    requires_dealer_code   integer      not null default 0,
    deprecated             integer      not null default 0,
    allowed_roles_csv      varchar(256) not null,
    allowed_brands_csv     varchar(64)  not null
);

-- Seed: identical to poc/apps/iam-broker/src/lib/target-systems.js
insert into ia_tb_sso_sys_mngmt_m values
  ('vendor-igtk',    'IGTK Vendor App',           'igtk',
   'http://vendor.sso.test:8000/sso/igtk',     null, 1, 0, 0,
   'DEALER_MANAGER,DEALER_STAFF,VENDOR', 'H,GMA'),

  ('vendor-saml',    'SAML Vendor App',           'saml',
   'http://vendor.sso.test:8000/sso/saml-acs', null, 1, 0, 0,
   'DEALER_MANAGER,DEALER_STAFF,VENDOR', 'H,GMA'),

  ('vendor-aes256',  'AES256 Vendor App',         'aes256',
   'http://vendor.sso.test:8000/sso/aes256',   null, 1, 1, 0,
   'DEALER_MANAGER,DEALER_STAFF',        'H'),

  ('vendor-rc4',     'RC4 Vendor App (DEPRECATED)', 'rc4',
   'http://vendor.sso.test:8000/sso/rc4',      null, 1, 1, 1,
   'DEALER_MANAGER,DEALER_STAFF',        'H,GMA'),

  ('vendor-wpc',     'WPC MOBIS Parts',           'wpc-otp',
   'http://vendor.sso.test:8000/sso/wpc',      null, 1, 1, 0,
   'DEALER_MANAGER,DEALER_STAFF',        'H');
