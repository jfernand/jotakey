# webauthn-topcoat on AWS

(c) Javier Fernandez @ JotaSoft 2026

A CDK app (TypeScript) that runs the demo relying party at **https://jotakey.casaroja.es**,
in `us-east-1`:

```
browser ──https──▶ API Gateway HTTP API ──▶ Lambda (x86_64) ──▶ DynamoDB
          jotakey.casaroja.es        Lambda Web Adapter          one table, TTL
          ACM certificate,           + the server unchanged      (../src/store/dynamo.rs)
          throttled 10/s, burst 20
```

- **Lambda Web Adapter** (an AWS-published layer) runs the Topcoat server as it is and turns
  each invocation into an HTTP request on port 8080. The server reads `ORIGIN` and
  `DYNAMODB_TABLE` from the function's environment.
- **API Gateway** serves only the custom domain (its default `execute-api` URL is off), so
  the origin WebAuthn checks and the cookies' host are always `jotakey.casaroja.es`. Its
  stage throttle is the demo's only rate limit, and it applies to the whole API.
- **Route 53:** the certificate is validated through the `casaroja.es` zone, and an alias
  record points the name at the API.

Two stacks:

| Stack | Holds | On `cdk destroy` |
|---|---|---|
| `JotakeyRpState` | the table: accounts, credentials, counters | kept: termination protection, deletion protection, `Retain`, point-in-time recovery |
| `JotakeyRp` | certificate, function, API, DNS record, logs (30 days) | removed |

The RP ID is the domain. Credentials are bound to it, so changing `domainName` later
strands every registered key.

## Deploy

Needs Docker, Node and AWS credentials for the account. The account is already
bootstrapped for CDK in `us-east-1`.

```sh
infra/build.sh                 # the Lambda binary, built in cargo-lambda's container
cd infra
npm ci
npx jest                       # synthesis tests
npx cdk diff                   # review what would change
npx cdk deploy --all
```

The first deploy waits for the certificate to validate (a few minutes). Then open
https://jotakey.casaroja.es.

After a code change: commit it, then `infra/build.sh` and `npx cdk deploy JotakeyRp`. Check
the deployment with the smoke test (from `examples/webauthn-topcoat`), which cleans up after
itself:

```sh
uv run -q --with cbor2 --with requests --with cryptography \
    python3 -I smoke_test.py https://jotakey.casaroja.es
```

The page's footer names the commit the server was built from, linked to GitHub, so push
before deploying. `build.sh` refuses uncommitted changes to the demo; `ALLOW_DIRTY=1` builds
anyway, and the footer then says "local build".

The settings are in `cdk.json`'s context (`domainName`, `zoneName`, `hostedZoneId`); override
one with `-c key=value`.

## Cost

At a demo's traffic, cents a month: Lambda, DynamoDB on-demand and the HTTP API are billed
per request; point-in-time recovery per GB stored (the table is kilobytes); the Route 53
zone already exists. ACM certificates are free.

## Known findings

`npm audit` reports `brace-expansion` (GHSA-q2hr-2g5m-vwhr and two related denial-of-service
advisories) inside `aws-cdk-lib`'s bundled `minimatch`. It runs only at synthesis, on the
CDK's own glob patterns, and never in the deployed server. A bundled dependency cannot be
overridden; it goes when aws-cdk-lib updates its bundle.
