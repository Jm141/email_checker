# Upgraded Node.js Email & Domain Checker

## What is improved

- Correctly distinguishes EMAIL, DOMAIN, and INVALID.
- Cleans pasted Markdown email links, `mailto:`, and URL-style input.
- Checks MX records.
- Detects common mail providers.
- Performs a more reliable line-based SMTP conversation instead of searching one shared buffer.
- Uses concurrency limits so bulk checks do not open too many SMTP connections at once.
- Configurable SMTP timeout.
- Handles SMTP errors and timeouts as `NOT_VERIFIABLE`, not automatically invalid.
- Shows `NO_MX` when the domain has no usable MX records.
- Shows `MAIL_DOMAIN` for a domain that has mail hosting.
- Bulk checking up to 5,000 unique lines per request.
- Export results to CSV.
- Includes `/health` endpoint.

## Status meanings

- DELIVERABLE: SMTP server accepted the recipient during this check.
- NOT_DELIVERABLE: SMTP server explicitly rejected the recipient with a 5xx response.
- NOT_VERIFIABLE: SMTP verification was blocked, timed out, failed, or returned an ambiguous response.
- NO_MX: Domain has no usable MX records.
- MAIL_DOMAIN: Domain has MX/mail hosting configured.
- MX_ONLY: SMTP check was disabled, but MX was found.
- INVALID: Input is neither a valid email nor a valid domain.
- ERROR: Unexpected server-side error.

## Important limitation

A direct SMTP check cannot guarantee that a mailbox exists. Large providers can block recipient probing, use catch-all behavior, greylisting, rate limiting, or other anti-enumeration techniques.

Therefore:

    NOT_VERIFIABLE != INVALID

For high-volume email-list validation, use a dedicated email verification provider/API if you need stronger mailbox-risk classification.

## Run

Install Node.js 18+.

Open a terminal in this folder:

    npm install
    npm start

Then open:

    http://localhost:3000

For development:

    npm run dev

## If SMTP always times out

This is often a network restriction rather than a bug in the checker. Many hosting environments and ISPs restrict outbound TCP port 25.

You can still use the MX-only mode by unchecking "SMTP mailbox check". For actual mailbox verification at scale, use a dedicated verification API.
