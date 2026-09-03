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
- `makefile` — cible `bench` : `grep -A1 "Logs"` remplacé par un awk qui imprime
  le bloc de logs entier. L'ancien filtre ne gardait qu'une ligne après chaque
  en-tête `Logs:` et perdait donc silencieusement toute mesure émise en second
  dans un test — c'est-à-dire les trois chiffres FAST.
- `test/Benchmarks.t.sol` — ajout des mesures `NIST HashToPoint FAST`,
  `Verify NIST FAST`, `testBenchHashToPointNISTFastAlone` (mémoire fraîche) et
  `testBenchF1600` (une permutation, les deux voies). Les mesures existantes sont
  inchangées. Le vecteur de sortie rapide est asserté contre `expected_hash`,
  donc l'égalité bit à bit est testée, pas supposée.

## [unreleased] — 2026-09-02 — NTT packée SWAR (aller seulement)

### Added
- `src/ZKNOX_NTT_falcon_packed.sol` — NTT directe Falcon-512 en SWAR packé :
  128 mots de quatre lanes de 64 bits, coefficient 4w+j en lane j du mot w.
  q tenant sur 14 bits, une lane de 64 laisse 50 bits de marge : les sommes
  restent NON RÉDUITES sur les neuf couches, seule la multiplication par le
  twiddle est réduite, d'un seul pas de Barrett (M40 = floor(2^40/q)).
  Couches t = 256..4 alignées sur les mots, une multiplication scalaire pour
  quatre papillons ; t = 2 et t = 1 traitées dans le mot.
  Fournit aussi `_packFromCompact` et `_unpackTo512`.
- `test/ntt_packed.t.sol` — différentiel contre `_ZKNOX_NTTFW_vectorized` :
  8 vecteurs fixes, 256 tirages de fuzz, et le cas saturé (tous les
  coefficients à q-1, le pire pour la croissance des lanes). 4/4.

### Measured
| Chemin (depuis la forme compacte) | gas |
|---|---:|
| `Expand` + `NTTFW` (actuel) | 489 011 |
| `_packFromCompact` + `_nttFwPacked` | 219 120 |
| | **2,23x** |

`_nttFwPacked` seule : 189 803 contre 424 743.

### Bounds
Barrett laisse un résidu < 2q (12 316 mesuré au pire sur 4x10^5 tirages,
soit 1,001q). La branche soustractive ajoute un biais packé de 4q pour rester
positive par lane, donc la borne croît de 4q par couche : 37q = 454 693 < 2^19
après neuf couches. Le produit twiddle vaut alors < 2^33 et la multiplication
de Barrett < 2^59,4, tous deux dans la lane. Aucune retenue inter-lane.

- `src/ZKNOX_falcon_core_packed.sol` — `falcon_core` sur la NTT packée. Deux
  suppressions au-delà de la NTT : la clé publique est consommée directement en
  forme compacte (les deux `Expand` disparaissent), et l'aller-retour
  `Compact` -> `Expand` sur s1, identité pour des coefficients < 2^16, est
  supprimé. `falcon_normalize` est inchangée.
- `src/ZKNOX_falcon_turbo.sol` — `ZKNOX_falcon_fast` + coeur packé, mêmes règles
  de liaison du helper (`EXTCODEHASH`).

### Measured (packed, suite)
| | avant | après | ratio |
|---|---:|---:|---:|
| `NTTFW` (depuis compact) | 489 011 | 219 120 | 2,23x |
| `NTTINV` | 456 267 | 251 983 | 1,81x |
| `HALFMUL` complet | 1 154 793 | 579 281 | 1,99x |
| `falcon_core` | 1 414 965 | 763 951 | 1,85x |
| **`verify` NIST bout en bout** | **1 962 789** | **1 327 039** | **1,48x** |

Cumulé depuis l'origine : 3 910 833 -> 1 327 039, soit **2,95x**.

### Déroulage et fusion — essayé puis ÉCARTÉ
Trois passes successives sur la NTT directe, chacune mesurée :
189 803 (boucles) -> 174 775 (boucle interne deroulee x4) -> 169 774 (boucle de
couches deroulee, m/twds/offsets en immediats). **10,5 % au total**, pas le
facteur 2 attendu par analogie avec l'amont ML-DSA.

Le corps d'un papillon-mot fait ~50 gas d'opcodes reels pour ~240 mesures. Le
delta n'est ni la boucle ni les acces memoire : c'est le brassage de pile du
codegen legacy. Preuve : `--via-ir` echoue avec « Could not create stack layout
after 1000 iterations », et l'inlining manuel des fonctions Yul avait deja rendu
8 % plus tot pour la meme raison. J'ai teste cette hypothese : **elle est fausse**. Voir ci-dessous.

Cout : `ZKNOX_falcon_turbo` passait de 9 814 a 14 255 octets. 4 441 octets pour
20 020 gas, soit ~888 000 gas de deploiement pour economiser 20 000 par
verification — amorti en 44 signatures, et 4,4 Ko pris sur la marge EIP-170.
**Le deroulage n'est PAS dans cette version** : `ZKNOX_NTT_falcon_packed.sol`
est la variante a boucles, lisible, 9 814 octets. Le code deroule reste
disponible si la NTT redevient le goulot ou si la contrainte de taille saute.

### Differential coverage
`test/ntt_packed.t.sol` : NTT directe, NTT inverse, HALFMUL et `falcon_core`
comparés à leurs références, 4 campagnes de fuzz de 256 tirages chacune, plus
6 vecteurs fixes par étage et le cas saturé (tous coefficients à q-1). 10/10.
`Verify NIST TURBO` est mesuré sur le vrai vecteur KAT et rend true.

### via-IR : mesuré, et ce n'est pas le levier
`src/ZKNOX_NTT.sol` fait planter le generateur de layout de pile de solc 0.8.25
sous `--via-ir` (`StackHelpers.h`, « Could not create stack layout after 1000
iterations »). **Bug preexistant, sans rapport avec ce travail** : le depot echoue
pareil avec les fichiers packes retires. Seul ce fichier est en cause, les 17
autres de `src/` compilent. Le profil `lite` du depot, qui porte `via_ir = true`,
est donc inutilisable en l'etat.

En excluant ce fichier, mesure sous via-IR :
| | legacy | via-IR | gain |
|---|---:|---:|---:|
| `_nttFwPacked` | 169 774 | 163 336 | 3,8 % |
| `falcon_core` packe | 748 923 | 726 362 | 3,0 % |
| `NTTFW` baseline | 424 743 | 398 494 | 6,2 % |

3 a 4 %, pas le facteur espere.

### Plancher du design actuel
Le corps d'un papillon-mot aligne coute ~120 gas en comptant les DUP et PUSH
(que j'avais omis dans l'estimation initiale a 50), pour 232 mesures. Il n'y a
pas de facteur 5 cache : le design est proche de son plancher. Le levier
structurel restant est de passer a **8 lanes de 32 bits** au lieu de 4 de 64 :
q tenant sur 14 bits, 64 mots suffiraient au lieu de 128. Le produit twiddle
(2^33) ne tient pas dans 32 bits, il faudrait separer lanes paires et impaires
avant chaque multiplication, donc 2 multiplications et 2 Barrett par mot de 8
coefficients au lieu de 1 et 1 par mot de 4 : arithmetique inchangee par
coefficient, mais moitie moins de loads, stores et iterations. Estimation
25-30 %, non mesuree.

### Not done yet
Lanes de 32 bits, `falcon_normalize` packée (171 k, encore en
un-coefficient-par-mot alors que s1 arrive packé), `verifyNISTCompliant`,
et remonter le bug via-IR de `ZKNOX_NTT.sol`.

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


### Piste explorée, non implémentée : lanes de 32 bits
8 coefficients par mot au lieu de 4 exige d'abandonner Barrett pour Montgomery :
reduire un produit de 33 bits par Barrett demande ~60 bits d'espace de travail
(x*M40 = 2^60), quelle que soit la constante. Baisser le shift ne sauve rien —
a s=26 le residu part a 170q. Montgomery avec R = 2^16 et q' = 12287 tient dans
32 bits (intermediaire le plus large 2^31, soit 49,7 % de la lane avec une
reduction partielle SWAR toutes les deux couches). Modele Python valide contre
`_ZKNOX_NTTFW_vectorized` sur 6 vecteurs dont le cas sature.
Gain estime 20-25 % par NTT (~7-8 % du verify) : les 6 couches alignees passent
de 448 a 192 papillons-mots, mais les 3 couches intra-mot sont un match nul
exact (t=1 demande 4 twiddles distincts par mot en 32 bits contre 2 en 64) et
REDC coute 7 opcodes contre 5 pour Barrett. Rapport gain/risque juge inferieur
a celui de `falcon_normalize` packee.
