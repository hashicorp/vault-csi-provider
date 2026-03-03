-- Copyright IBM Corp. 2019, 2025
-- SPDX-License-Identifier: BUSL-1.1

CREATE ROLE "{{name}}" WITH LOGIN ENCRYPTED PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";