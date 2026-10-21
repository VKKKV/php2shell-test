# Security policy and scope

This repository ships a **deliberately vulnerable** PHP lab and working
exploit chains. It exists for education, defensive research and regression
testing of session-serialization hardening.

## Allowed use

- Your own machine, your own containers, your own test environments.
- CTFs, labs, trainings and research where you have explicit authorization.

## Not allowed

Running these chains against systems you do not own or lack written
permission to test is illegal in most jurisdictions. The authors do not
condone and are not responsible for unauthorized use.

## Design guardrails

- The lab publishes nginx only on loopback (`127.0.0.1`) — never on `0.0.0.0`.
- php-fpm is never published to the host; nginx reaches it over the compose
  network.
- Containers run `read_only`, `no-new-privileges`, with pids/memory limits and
  no `privileged`/`seccomp:unconfined` flags.
- Every generated file lives under `lab/` (gitignored) and the compose project
  name is derived from the checkout path, so parallel clones do not collide.
- `down` removes containers and volumes; nothing persists after a teardown.

If you find a problem with the lab's isolation (not with the intentional
vulnerability itself), open an issue with the compose config and the
`docker inspect` output.
