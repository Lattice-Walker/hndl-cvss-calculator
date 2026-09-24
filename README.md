# HNDL-adjusted CVSS v4.0 calculator

A static web page that scores a TLS endpoint twice: once against an ordinary present-day attack and once against Harvest-Now-Decrypt-Later. It then combines the two into one score that fits the standard CVSS severity bands.

## How the score works

Both vectors are scored with the official FIRST CVSS v4.0 algorithm, so each score matches what the [FIRST calculator](https://www.first.org/cvss/calculator/4.0) gives.

The deprecation vector ($S_dep$) covers a padding-oracle-class attack on deprecated TLS. It defaults to `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`, which scores 6.3.

The harvest vector ($S_harv$) covers passive collection followed by later decryption. It defaults to `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H`, which scores 8.2. Exploit Maturity is locked to Not Defined on this vector. The lack of a quantum computer today is the premise of the threat, so it should not lower the score.

The temporal factor T comes from Mosca's inequality and three estimates in years:

- DL: how long the data must stay confidential
- MT: how long migration to hybrid or post-quantum key exchange will take
- QT: years until a cryptanalytically relevant quantum computer is assumed to exist

```
G = DL + MT - QT
T = 0                  if G <= 0
T = 1                  if G > 0 and QT = 0
T = min(1, G / QT)     if G > 0 and QT > 0

S_HNDL = max(S_dep, T * S_harv)
```

The page also recomputes $S_HNDL$ at $QT = 10$, $15$ and $20$ and marks the worst case, which is the figure to record.

## Coherence rules

The two vectors describe different attacks on one endpoint, so they are free to differ — the defaults already differ on AC, VC and VI. Some combinations are still contradictory, and the page blocks them rather than scoring them. Hovering a blocked option gives the reason; clicking one states it inline.

Because the harvest attacker is passive and retrospective, the harvest vector pins `AC:L`, `PR:N`, `UI:N`, `VI:N` and `VA:N`, and rejects `CR:X` (which CVSS v4.0 scores identically to `CR:H`). Because that attacker reads the whole plaintext of the same sessions, the harvest vector must be at least as severe as the deprecation vector on `AV`, `AT`, `VC` and `SC`; the rule is enforced from both sides. Inside the deprecation vector, `MSI:S` or `MSA:S` cannot be combined with Supplemental `S:N`.

Vectors arriving in a shared link are repaired towards the stricter value and the change is reported. Contradictions that are not a single choice — identical vectors, `DL = 0` with a raised `CR`, `QT = 0`, a recorded figure below the worst sampled horizon, or environmental and threat metrics used on one vector but unavailable on the other — are listed as notes beside the result instead of being blocked.
