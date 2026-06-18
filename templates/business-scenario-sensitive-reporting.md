# Sensitive Reporting Scenario

Use this template when the target handles whistleblower, informant, hotline, incident-report, petition, complaint, or public-safety reporting workflows, including WeChat Mini Programs backed by a web/API host.

## Hard Rules

| Topic | Rule |
|------|------|
| Same-host Web | If a Mini Program backend host is in scope, check whether the same host serves Web pages such as `/`, `/login`, `/admin`, `/xsjb/`, `/jdcx/`, or feature paths unless the user excludes Web. |
| Reporter Identity | Treat reporter identity, phone state, openid/userId linkage, case status, attachment state, and report content as sensitive. |
| Single Account | With one account, validate trust-boundary behavior only. Do not claim cross-user read/delete unless paired-account or vendor evidence proves it. |
| State Change | Do not create, update, submit, delete, or send SMS unless the user explicitly authorizes that exact operation. |
| Test Data | Numeric IDs, sequential IDs, `1`, `2`, `admin`, `test`, or plausible production IDs are not safe test data. Use synthetic UUID-like values containing `appsec-test`. |
| Evidence | Store only redacted reporter identifiers and sanitized PoCs. Do not store real PII outside `sessions/`. |

## Static-First Flow

1. Extract backend hosts, request paths, methods, headers, storage keys, and identity-bearing parameters.
2. Map pages to backend APIs: report submit, progress query, report detail, profile, phone binding, attachments, articles, search, admin/web pages.
3. Identify same-host Web surface and ask or test within scope.
4. Record single-account validation limits before live replay.
5. Generate the attack queue from current artifact and live fingerprint evidence, not from L3 history.

## Live Validation Limits

Safe with one account:

- Own-account baseline request.
- No-auth comparison.
- Synthetic identity field comparison using a clearly fake value.
- One request per hypothesis, no iteration.

Requires explicit extra authorization:

- Paired-account BOLA confirmation.
- Any attachment delete or report submission.
- SMS/captcha abuse validation.
- Numeric or plausible production IDs.

## Severity Override

Escalate reporter-impact findings by one level when they expose or manipulate reporter identity, phone state, case content, progress state, or evidence attachments. In this scenario, classify by reporter impact rather than generic request impact.

## Reporting Notes

- State whether Web was tested and why.
- For each confirmed finding, include a sanitized minimal PoC and raw evidence path.
- For unconfirmed cross-user impact, say exactly what is proven and what requires paired-account/vendor validation.
