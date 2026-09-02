# VERSION.md — changelog

## [unreleased] — 2026-09-02 — SHAKE256 externalisé (helper Keccak-f[1600] déroulé)

### Added
- `src/ZKNOX_shake_fast.sol` — XOF SHAKE256 adossée à un contrat helper externe
  contenant la permutation Keccak-f[1600] entièrement déroulée (21 622 octets de
  runtime brut, `helpers/f1600_170.hex` de fireblocks-labs/evm-ml-dsa-verifier, MIT).
  Expose `f1600Fast170`, `shake256Fast`, `hashToPointNISTFast`.
  L'échantillonneur par rejet de `hashToPointNISTFast` est identique octet pour
  octet à celui de `hashToPointNIST` : seule la XOF change.
- `src/ZKNOX_falcon_fast.sol` — `ZKNOX_falcon` câblé sur `hashToPointNISTFast`,
  helper passé au constructeur et conservé en `immutable`. `falcon_core`,
  contrôles de paramètres et encodages inchangés.
- `test/f1600_170.hex` — runtime du helper (déployé en `setUp` via ffi + CREATE).
- `test/falcon_fast_helper.t.sol` — tests de la liaison du helper : primitive
  d'attaque (helper menteur -> le message ne lie plus), l'ancienne liaison
  `code.length != 0` l'acceptait, la liaison `EXTCODEHASH` la refuse à la
  construction, mutation d'un octet refusée, re-contrôle par appel après
  substitution de code, et non-régression sur le helper honnête. 7/7.

### Changed
- `test/Benchmarks.t.sol` — ajout des mesures `NIST HashToPoint FAST`,
  `Verify NIST FAST`, `testBenchHashToPointNISTFastAlone` (mémoire fraîche) et
  `testBenchF1600` (une permutation, les deux voies). Les mesures existantes sont
  inchangées. Le vecteur de sortie rapide est asserté contre `expected_hash`,
  donc l'égalité bit à bit est testée, pas supposée.

### Measured (forge 1.4.2-nightly c808c4cd, solc 0.8.25, evm cancun, optimizer 10000, legacy codegen)
| Mesure | Avant | Après | Ratio |
|---|---:|---:|---:|
| Keccak-f[1600], 1 permutation | 167 646 | 41 743 | 4,02x |
| `hashToPointNIST` (mémoire fraîche) | 2 183 809 | 535 067 | 4,08x |
| `ZKNOX_falcon.verify` (NIST) | 3 910 833 | 1 962 789 | 1,99x |

Part de la SHAKE dans le verify NIST : 55,8 % -> 27,3 %.
Coût ponctuel : déploiement du helper, 21 622 octets -> ~4,32 M de gas de code,
partagé par tous les vérifieurs de la chaîne.

### Security
- Helper lié par `EXTCODEHASH` (`F1600_CODEHASH =
  0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b`), contrôlé
  au constructeur ET re-contrôlé à chaque `verify`. Coût : +129 gas sur le verify,
  l'`EXTCODEHASH` absorbant les 2 600 gas de compte froid que le premier
  `STATICCALL` payait. Remplace le `code.length != 0` initial, qui laissait le
  déployeur choisir ce que SHAKE256 signifie.

### Tests
`forge test` : 98/98 OK (aucune régression). Le vecteur NIST hash-to-point sort
identique par les deux voies.
