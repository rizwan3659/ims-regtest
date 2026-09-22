# ims-regtest

A load and conformance tester for IMS registration, in C. Each simulated UE
performs the real exchange:

```
UE                                   S-CSCF
 │ REGISTER (no credentials)  ─────▶ │
 │ ◀───── 401 + WWW-Authenticate      │   digest challenge (nonce, qop=auth)
 │ REGISTER + Authorization   ─────▶ │   MD5 digest response, CSeq + 1
 │ ◀───── 200 OK (Contact;expires)    │
```

- **Open-loop load:** UE *i* starts at `t0 + i/rate` whether or not earlier
  registrations have finished. A closed-loop tester slows down when the
  target slows down, so it hides the queueing delay you're trying to find.
- **Retransmissions** on T1, 2·T1, 4·T1 and so on (RFC 3261 UDP client
  behaviour). A request that is still unanswered after `max_tries` sends is
  counted as timed out.
- **Response checking:** each answer is matched to its UE by Call-ID and to
  its request by CSeq. Stale answers to retransmitted requests are ignored.
- **Result:** registrations/s and REGISTER-to-200 latency percentiles, for
  successful registrations only.
- **Stub S-CSCF included:** it really verifies the digest, using a stateless
  nonce bound to the Call-ID. It can drop N% of requests to simulate a lossy
  path. That's how the tester is tested.

> This is a clean-room tool of the kind I used when deploying and testing
> IMS modules for performance and LTE-core integration at C-DOT (BSNL 4G
> rollout). It contains no C-DOT code or data. The numbers below come from
> this repository only, against its own stub registrar.

## Build and run

```sh
make test     # MD5/digest vectors; 2000 UEs; 10% loss; wrong password → 403
make asan tsan
./ims-regtest --ues 20000 --rate 5000                 # against the built-in stub
./ims-regtest --target 10.0.0.5:5060 --ues 5000 --rate 500   # against a real registrar
```

## Results against the stub registrar

2-vCPU cloud VM, loopback, 20,000 UEs:

| Offered rate | Achieved | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| 5,000/s | 4,998/s | 0.14 ms | 0.29 ms | 2.50 ms |
| 20,000/s | 19,971/s | 0.15 ms | 1.16 ms | 4.53 ms |
| 50,000/s | 49,774/s | 2.66 ms | 9.49 ms | 10.89 ms |

The step at 50,000/s is the stub's single thread starting to queue. That's
the kind of knee this tool exists to find in a real S-CSCF.

With 10% of requests dropped (`--loss 10 --t1 50`), all 1,000 UEs still
register. 212 retransmissions covered exactly the 212 dropped requests, and
the latency tail moves to multiples of T1 (p95 50 ms, p99 150 ms), as
expected.

## Scope and honesty notes

- **Digest MD5 only.** Real IMS UEs authenticate with IMS-AKA
  (`AKAv1-MD5`, keys from the ISIM), which this tool does not do. A challenge
  with `algorithm=AKAv1-MD5` is rejected rather than answered wrongly.
- **MD5 is here only because SIP digest uses it.** It is not a safe hash for
  new designs.
- **UDP only.** No TCP or TLS, no IPSec (see my `xfrm-async-sa` repo for the
  P-CSCF IPSec side), and no re-registration or de-registration yet.

## Layout

| File | What it does |
| --- | --- |
| `src/md5.c` | RFC 1321 MD5, checked against the RFC's test suite |
| `src/digest.c` | Challenge parser (quote-aware, so `nonce=` inside a quoted realm can't be injected) and RFC 2617 response |
| `src/loadgen.c` | Open-loop scheduler, per-UE state machine, retransmission, percentiles |
| `src/registrar.c` | Stub S-CSCF: 401 challenge, digest verification, 200/403, loss injection |

MIT licensed.
