# VERSION.md — changelog

## [unreleased] — 2026-09-05 — profil de compilation : solc 0.8.30, via-IR, `optimizer_runs = 1000000`

### Measured (`forge test test/Benchmarks.t.sol`, vecteur KAT NIST)
| Vérifieur | 0.8.25 legacy, runs 10000 (avant) | **0.8.30 via-IR, runs 1e6 (après)** |
|---|---:|---:|
| `ZKNOX_falcon_fused.verify` | 755 683 | **726 898** (−3,8 %) |
| `ZKNOX_falcon_turbo.verify` | 1 327 039 | 1 315 117 |
| `ZKNOX_falcon_fast.verify` | 1 962 789 | 1 975 365 |
| `ZKNOX_falcon.verify` (référence scalaire) | 3 910 833 | 4 025 409 (+2,9 %) |

Depuis l'origine : 3 910 833 → 726 898, **5,38x**. Noyaux : NTTFW fusionnée
119 454 → 105 416, produit + INTT 131 149 → 116 898, normes 33 030 → 28 177,
`falcon_core_fused` 282 086 → 249 705 ; hash-to-point packé 421 498 →
425 993 (+1 %, le sampler préfère le legacy). Runtime `ZKNOX_falcon_fused`
19 342 → 18 254 octets ; 141/141 tests.

### Pourquoi
Transfert de ce qui a été appris sur ZKNoxHQ/ETHDILITHIUM (ADR-004 de ce
dépôt-là) : les noyaux packés sont nettement moins chers sous le pipeline IR
(ordonnancement de pile), et `optimizer_runs` doit être assez haut pour que
l'optimiseur de constantes de solc garde les constantes SWAR de 32 octets en
PUSH32 au lieu de les recopier par `codecopy` à chaque usage. Vérifié ici :
aucun `codecopy` de constante dans `ZKNOX_falcon_fused` sous aucun des deux
profils (solc 0.8.25 legacy n'était pas touché), le gain vient du pipeline IR.
via-IR avait été écarté en début de chantier (3-4 % mesurés sur la NTT
scalaire) ; avec solc 0.8.25 il ne compile pas la transformée fusionnée
(« Could not create stack layout after 1000 iterations »), solc 0.8.30 la
compile.

### Ce qui ne transfère pas d'ETHDILITHIUM
- Montgomery : à q = 12289 le Barrett à une étape (5 ops, 2 multiplications)
  bat un REDC à R = 2¹⁶ (6 ops, 3 multiplications), +5 gas par papillon-mot.
  Montgomery ne gagnait chez ML-DSA que parce que q = 23 bits impose un
  Barrett à deux étapes.
- Le layout packé, le spread de la forme compacte, le produit pointwise
  replié, les normes SWAR : déjà ici, c'est d'ici qu'ils viennent.

### Changed
- `foundry.toml` : `solc_version = "0.8.30"`, `via_ir = true`,
  `optimizer_runs = 1000000` dans les profils `default` et `ci` (`lite`
  passe en 0.8.30 aussi). Le bytecode déployé de tous les contrats change ;
  la référence scalaire `ZKNOX_falcon` et `ZKNOX_falcon_fast` perdent 1 à 3 %,
  ce sont les baselines, pas les produits.

## [unreleased] — 2026-09-03 — NTT radix-8 fusionnée, sampler Yul, normes SWAR (`ZKNOX_falcon_fused`)

Reprise des idées restantes de fireblocks-labs/evm-ml-dsa-verifier (cca262b)
après la SHAKE externe et la NTT packée : fusion de couches, décodage direct
dans le layout de l'arithmétique, échantillonneur sans `bytes`.

### Added
- `src/ZKNOX_NTT_falcon_fused.sol` (GÉNÉRÉ par `pythonref/gen_ntt_fused.py`,
  puis `forge fmt`) — la NTT packée réorganisée en passes radix-8 : chaque
  octet de mots est chargé une fois, traverse trois couches sur la pile et
  est stocké une fois (8 loads + 8 stores pour 12 papillons-mots au lieu de
  24 + 24, une itération de boucle pour 12 papillons au lieu d'une par
  papillon). Mêmes tables `psirev`, même twiddle par papillon que
  `ZKNOX_NTT_falcon_packed.sol`.
  - aller : A (t=256,128,64) lit directement la forme compacte (le spread
    16 bits -> lanes de 64 est une multiplication par `1 + 2^48 + 2^96 + 2^144`
    masquée, 4 ops au lieu de 15), B (t=32,16,8) avec les 7 twiddles du bloc
    packés dans le scratch 0x00, C (t=4 sur la paire, puis t=2 et t=1 dans le
    mot en SWAR, Barrett, biais 2q par couche). Sortie lazy < 19q.
  - inverse : C' (produit pointwise avec la clé publique COMPACTE replié dans
    l'extraction scalaire des lanes, `mulmod` exact ; t=1, t=2 scalaires ;
    t=4 packé), B' (t=8,16,32, sommes jamais réduites), A' (t=64,128,256,
    n^-1 replié dans la dernière couche, `psirev[1]*n^-1 = 1371` en littéral,
    sortie CANONIQUE). Plus de `_packFromCompact(ntth)`, `_vecMulPacked` ni
    `_unpackTo512`.
  - `_s2NormCompact` (range check + ||s2||² sur les 32 mots compacts) et
    `_normS1Packed` (||h - s1||² sur les 128 mots packés) en SWAR sur des mots
    de seize champs de 16 bits : canonicalisation et centrage par bit de
    signe de champ, somme des carrés par `E * rev(E)` (position 7 du produit
    de deux mots à huit champs de 32 bits = somme des huit carrés).
- `pythonref/gen_ntt_fused.py` — générateur. Les corps radix-8 (12 papillons)
  et les passes intra-mot (4 paires déroulées par mot de table) sont
  répétitifs et la discipline de pile (≤ 16 slots, codegen legacy, pas de
  spill) dépend de l'ordre exact des loads, temporaires et blocs : une seule
  source pour les six passes.
- `pythonref/model_ntt_fused.py` — modèle Python du schedule fusionné, validé
  couche par couche contre un modèle de la NTT packée sur 30 tirages dont le
  cas saturé (tous les coefficients à q-1) ; chaque multiplication Barrett
  asserte la localité de lane (`x*M40 < 2^64`), chaque branche soustractive
  asserte sa positivité.
- `src/ZKNOX_HashToPoint_packed.sol` — `hashToPointNISTPacked` : même
  fonction que `hashToPointNIST` (lectures 16 bits big-endian, acceptation
  `< 5q`, `% q`, 512 coefficients), mais l'échantillonneur est en Yul et lit
  les 17 lanes de l'état de l'éponge (une inversion d'octets par lane) au lieu
  d'un bloc `bytes` de 136 octets, et écrit directement le layout packé
  (4 coefficients par mot). Plus de `tmp`, de squeeze, de bounds checks ni de
  `%` checké.
- `src/ZKNOX_falcon_core_fused.sol` — `falcon_core_fused(s2, ntth,
  hashedPacked)` : range check d'abord (un coefficient ≥ q est rejeté avant
  toute arithmétique, comme dans `falcon_normalize`), puis
  `s1 = _nttInvFusedMul(_nttFwFused(s2), ntth)`, norme = ||s2||² +
  ||h - s1||², accepte ssi ≤ `sigBound` (34 034 726). Même décision que
  `falcon_core`, assertée.
- `src/ZKNOX_falcon_fused.sol` — `ZKNOX_falcon_turbo` avec les deux
  remplacements. Même API `verify(h, salt, s2, ntth)`, même liaison
  `EXTCODEHASH` du helper (ADR-002), mêmes contrôles de longueur.
- `test/ntt_fused.t.sol` (12) — différentiel de la transformée fusionnée
  contre la packée (aller mod q avec borne 19q assertée ; produit + inverse
  exact et canonique), 8 vecteurs fixes, 256 tirages de fuzz par direction,
  cas saturés des deux côtés ; normes contre une réécriture de
  `falcon_normalize`, drapeau de range sur les 16 positions avec q, q+1,
  0x3fff, 0x4000, 0x7fff, 0x8000, 0xc001, 0xffff ; mesures de composants.
- `test/falcon_fused.t.sol` (14) — `hashToPointNISTPacked` contre
  `hashToPointNISTFast` (vecteur KAT, 256 tirages (salt, message), longueurs
  0..296 pour les chemins de padding) ; `falcon_core_fused` contre
  `falcon_core` des DEUX côtés de la borne (balayage d'amplitude d'erreur
  autour de s1, fuzz), sur la borne exacte (norme = sigBound acceptée,
  sigBound + 3 refusée : 34 034 726 = 5833² + 104² + 4² + 2² + 1²), s2 hors
  plage rejeté malgré une norme nulle, entrées aléatoires ; KAT NIST
  (`ZKNOX_falcon`, turbo et fused acceptent ; bit de signature, message et
  salt altérés refusés) ; contrôles de longueur ; liaison du helper.

### Changed
- `test/Benchmarks.t.sol` — `Verify NIST FUSED cost`, `Falcon core FUSED
  cost` (décision assertée égale à `falcon_core`), `NIST HashToPoint PACKED
  (fresh mem)`. Le bench du core lit `pkc` en mémoire une fois pour les trois
  cores (32 SLOAD froids = 67 k sinon comptés dans la première mesure).

### Measured (forge 1.4.2-nightly c808c4cd, solc 0.8.25, evm cancun, optimizer 10000, legacy codegen)
| Mesure | Avant (turbo) | Après (fused) | Ratio |
|---|---:|---:|---:|
| `verify` NIST, vecteur KAT | 1 327 039 | **755 683** | 1,76x |
| `falcon_core` (packé -> fusionné) | 748 923 | 282 086 | 2,66x |
| NTTFW depuis la forme compacte | 218 880 | 119 454 | 1,83x |
| pack + VECMUL + NTTINV + unpack | 358 244 | 131 149 | 2,73x |
| `falcon_normalize` -> `_s2NormCompact` + `_normS1Packed` | 171 236 | 33 030 | 5,2x |
| `hashToPointNIST` FAST -> PACKED (mémoire fraîche, 8 blocs) | 535 067 | 421 498 | 1,27x |

Depuis l'origine : 3 910 833 -> 755 683, **5,17x**.

Ventilation du verify KAT (10 permutations, 1 absorb + 9 squeeze) :
permutations 418 k (55 %), sampler ~30 k, core 282 k, glue ~25 k. Le helper
Keccak-f est désormais le plancher : le reste du chemin fait 340 k.

Profil des passes : radix-8 ≈ 25 k chacune (16 octets, ~130 gas par
papillon-mot, contre ~330 dans la version couche par couche) ; intra-mot
C = 53 k, C' = 75 k (le produit pointwise à 4 multiplicateurs distincts par
mot impose l'extraction scalaire).

Taille : `ZKNOX_falcon_fused` 19 342 octets de runtime (turbo : 9 814), marge
EIP-170 5 234. Le déroulage ×4 des passes intra-mot et les constantes de
32 octets répétées en sont la cause ; accepté.

### Bornes
- aller : lanes canoniques en entrée, +2q par couche (V < 2q par Barrett,
  biais 2q), donc < 19q après neuf couches ; produits twiddle < 19q·q < 2^28.
- inverse : lanes < 2q après C', les sommes doublent par couche sans
  réduction (< 16q après B', < 128q avant la dernière couche), branche
  soustractive `u + Kq - v` < 2Kq ; tout produit < 128q·q < 2^31, toute
  multiplication Barrett < 2^58 (localité de lane jusqu'à 2^64).
- normes : champs de 16 bits, `v < 2q` -> `v + 2^15 - q < 2^16` sans retenue ;
  carrés < 2^26, huit carrés < 2^29 dans un champ de 32 bits, la position 6
  du produit (< 7·2^26) ne déborde jamais dans la position 7.

### Essayé puis ÉCARTÉ (mesuré)
- intra-mot inverse en SWAR (pointwise par `mul` + masque de lane, GS t=1/t=2
  packés, sommes lazy jusqu'à 1024q, schedule de biais 8/16/32/64/128/256/512
  validé dans le modèle) : 139 709 contre 131 149 pour la version scalaire.
  `mulmod` (8 gas, exact) bat un Barrett de lane (~33 gas avec ses PUSH)
  quand il en faut un par lane de toute façon.
- intra-mot aller en scalaires `mulmod` : 130 206 contre 119 454 en SWAR
  (là, une multiplication sert deux lanes).
- curseurs de twiddles sur la pile + fonctions Yul pour l'intra-mot
  (première version) : 72 674 / 86 450 contre 52 908 / 75 201 déroulé, tous
  twiddles extraits par décalage immédiat, scratch 0x00 pour S4 et S2.

### Not done
- clé publique pré-packée 4×64 (SSTORE2) : ~-29 k mais change l'interface.
- replier `_normS1Packed` dans la passe A' (les lanes canoniques sont sur la
  pile avant le store) : ~-8 k, écarté pour garder `_nttInvFusedMul` testable
  seul.
- `verifyNISTCompliant`, `ZKNOX_ethfalcon` / epervier : non portés, même
  recette applicable.

### Tests
`forge test` : 141/141 (114 existants + 27 nouveaux).

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
