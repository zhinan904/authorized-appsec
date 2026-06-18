# Session Context

- session_id: S-001
- context: user
- status: valid
- source: login-api
- credential_type: cookie
- created_at: YYYY-MM-DD HH:MM
- updated_at: YYYY-MM-DD HH:MM
- expires_at: YYYY-MM-DD HH:MM

## Material

- cookie_name: session
- cookie_value: <redacted>
- token_type: none
- token_value: none
- api_key_name: none
- api_key_value: none

## Scope

- target: https://example.com
- target_type: url
- usable_for:
  - authenticated endpoints
  - user profile APIs

## Refresh Rules

- refresh_mode: re-login
- refresh_endpoint: POST /api/v1/login
- refresh_trigger:
  - 401 response
  - redirect to login
  - explicit token expiry

## Notes

- `context` values: `anonymous` / `user` / `admin` / `service`
- `status` values: `valid` / `expired` / `invalid` / `unavailable`
- Sensitive session material should be redacted or removed before formal publication