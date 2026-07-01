# Payload Index — choose by parameter shape, not by guess

> **Purpose.** When validating a queue item, load the **one** payload file that
> matches the parameter you are testing. Do not load the whole library, and do
> not pick by the endpoint's "obvious" vuln class — a single parameter often
> carries several classes (see "parameter × class" in SKILL.md). This index maps
> **what the parameter looks like** → **which payload file(s) to load**, so the
> choice is mechanical, not intuitive.
>
> Most missed findings come from testing a parameter against only its first-guess
> class (e.g. an `order_no` tested for IDOR but not SQLi). Use this table in
> Round 2 (depth pass): for each parameter, load **every** file its row lists,
> not just the first.

## How to use

1. Identify the parameter's *shape* (its value pattern and field name).
2. Look it up below → load the listed payload file(s).
3. A parameter usually matches **more than one row** — load all of them. That is
   the point: `order_no` is both an ID surface (idor) and an injection point
   (sqli); testing only one is the coverage sink this index exists to close.

## Parameter shape → payload file(s)

| Parameter shape / field name | Primary payload | Also test (Round 2) |
|------------------------------|-----------------|--------------------|
| Numeric / sequential ID (`id`, `order_no`, `user_id`, `product_no`, `merchant_id`) | `idor.md` | `sqli.md` (or `api-sqli.md`), `api-business-logic.md` |
| URL-shaped / fetch target (`url`, `image_url`, `redirect`, `next`, `callback`, `target`, `ref`) | `ssrf.md` (or `api-ssrf.md`) | `open-redirect.md`, `cors.md` |
| Redirect / navigation (`redirect`, `return_url`, `next`, `goto`, `continue`) | `open-redirect.md` | `ssrf.md` |
| Free text / reflected (`q`, `keyword`, `search`, `name`, `comment`, `description`, `message`) | `xss.md` (or `dom-xss.md`) | `sqli.md`, `ssti.md` |
| Filename / upload field (`filename`, `file`, `avatar`, `image`) | `file-upload.md` | `path-traversal.md` |
| Path / directory (`path`, `file`, `page`, `template`, `lang`, `dir`) | `path-traversal.md` | `file-inclusion.md`, `file-read.md`, `ssti.md` |
| Money / quantity / amount (`price`, `amount`, `refund_amount`, `quantity`, `total`, `discount`) | `api-business-logic.md` | `race-condition.md` (for state-changing amounts), `sqli.md` |
| Points / score / probability (`points`, `probabilities`, `score`, `weight`) | `api-business-logic.md` | `race-condition.md` |
| Boolean / role / flag (`is_admin`, `role`, `active`, `status`, `verified`) | `api-business-logic.md` (mass assignment) | `idor.md` |
| Token / credential (`token`, `auth_token`, `sign`, `signature`, `api_key`, `secret`) | `api-auth.md` | `session-management.md`, `jwt.md` (if JWT-shaped) |
| JWT (`eyJ...`) | `jwt.md` | `session-management.md`, `api-auth.md` |
| Session / cookie (`session`, `sid`, `PHPSESSID`, `csrf_token`) | `session-management.md` | `csrf.md`, `jwt.md` |
| Password / auth (`password`, `passwd`, `pwd`, `old_password`, `new_password`) | `password-policy.md` | `api-auth.md`, `default-credentials.md` |
| Phone / email / username (`phone`, `email`, `username`, `account`) | `api-auth.md` | `api-data-exposure.md`, `rate-limiting.md` |
| Captcha / OTP / SMS code (`captcha`, `sms_code`, `otp`, `code`, `verify`) | `api-auth.md` | `rate-limiting.md`, `mfa-bypass.md` |
| XML body / `Content-Type: xml` | `xxe.md` (or `api-xxe.md`) | `sqli.md` |
| JSON body with nested objects / arrays | `api-business-logic.md` | `prototype-pollution.md`, `nosqli.md` (if `$`-shaped) |
| NoSQL operators (`$where`, `$ne`, `$gt`, `$regex`) | `api-nosqli.md` | `api-business-logic.md` |
| GraphQL (`/graphql`, `query=`, `mutation`) | `api-graphql.md` | `idor.md`, `api-data-exposure.md` |
| Host header / `X-Forwarded-*` | `host-header.md` | `ssrf.md`, `cache-poisoning.md` |
| Content-Type / transfer-encoding manipulation | `http-smuggling.md` | `cors.md`, `crlf-injection.md` |

## Endpoint-class fallback (when no single parameter stands out)

If the endpoint is a known class but you are not sure which parameter, load the
class file and test every parameter in the request:

| Endpoint tells you | Load |
|--------------------|------|
| Login / registration / auth flow | `api-auth.md`, `password-policy.md`, `rate-limiting.md` |
| Admin panel / dashboard | `admin-panel.md`, `idor.md`, `api-business-logic.md` |
| File upload form | `file-upload.md`, `path-traversal.md` |
| Search endpoint | `sqli.md`, `xss.md` |
| Payment / recharge / refund / order | `api-business-logic.md`, `race-condition.md` |
| Chat / LLM / AI endpoint | `ai-security.md` |
| API config / actuator / debug | `api-config.md`, `api-data-exposure.md` |
| Webhook / callback / fetch-url | `ssrf.md`, `race-condition.md` |
| gRPC / protobuf | `grpc-protobuf.md` |
| WebSocket | `websocket.md` |

## Notes

- `api-*` variants are for JSON/REST API endpoints; the plain variant (e.g.
  `sqli.md`) is for traditional form/query-param contexts. When unsure, load
  both — they cover different injection styles.
- When a Round-1 verdict was `false_positive` for one class, Round 2 should still
  test the *other* classes in the "Also test" column before closing the endpoint.
- This index is advisory structure, not a gate. Its goal is to remove the "which
  payload do I pick?" guesswork that causes single-class testing.
