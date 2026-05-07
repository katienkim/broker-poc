-- The token column can hold large SAML XML that exceeds btree max row size.
-- This index was never useful anyway — lookups are by jti, not by token value.
drop index if exists ix_token_history_token;
