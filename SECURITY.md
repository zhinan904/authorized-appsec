# Security Policy

## Supported Scope

This project is a workflow and documentation skill for authorized web and application security assessment. It does not authorize testing against third-party systems.

Use this skill only when you own the target, operate the target, or have explicit permission to test it.

## Out of Scope

This public project does not support or accept requests for:

- phishing or social engineering;
- malware, persistence, stealth, or evasion;
- credential theft or credential dumping;
- lateral movement or post-exploitation;
- denial-of-service testing;
- destructive actions against production systems;
- testing targets without authorization.

## Reporting Security Issues

If you find a security issue in this project, report it privately to the maintainer before public disclosure.

Please include:

- affected file or script;
- reproduction steps using local test data only;
- expected and actual behavior;
- suggested fix, if available.

Do not include real target data, credentials, tokens, cookies, raw client evidence, screenshots, HAR files, or private reports.

## Sensitive Data Handling

Do not commit:

- `results/`;
- `l3/`;
- `references/` private extensions;
- raw request/response evidence;
- screenshots;
- HAR, Burp, PCAP, or database files;
- credentials, cookies, bearer tokens, API keys, or private keys.

