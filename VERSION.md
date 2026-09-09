# VERSION.md — changelog

## [unreleased] — 2026-09-09 — notre permutation Keccak-f[1600] (`test/f1600_zknox.hex`)

### Measured
| | gas |
|---|---:|
| helper Fireblocks, wrapper résident, une permutation | 40 448 |
| **notre helper, interface résidente, une permutation** | **39 974** (−1,2 %) |
| `ZKNOX_falcon8.verify`, KAT NIST, helper froid | 654 611 → **650 210** |

5,99x depuis l'origine. 153/153 tests ; helper de 23 846 octets, code hash
`0x661c9f13…3f409155`, trois interfaces : 800 octets = permutation sur 25
lanes propres, **801** = permutation sur 25 lanes répliquées (un octet ignoré
en plus, pour qu'aucune longueur de message alignée sur 32 octets ne
collisionne, l'entrée du hash final de ML-DSA faisant 832 octets), toute
autre longueur = SHAKE256 du calldata, 136 octets en sortie (l'entrée
groupée qu'utilise ETHDILITHIUM). Vérifié contre le helper Fireblocks par les
trois interfaces (forge : 16 états aléatoires, messages aléatoires) et contre
une référence Python sur un mini-EVM (`pythonref/check_keccak_helper.py`, qui
compte aussi le gas : 40 448 pour le wrapper Fireblocks, à 6 gas près de la
mesure forge ; 12 longueurs de message contre `hashlib.shake_256`).

### Le générateur (`pythonref/gen_keccak_helper.py`)
Même forme « Q » que Fireblocks (quatre copies de chaque lane de 64 bits par
mot de 256, état en mémoire, 24 tours en ligne droite) ; les choix qui font
la différence, tous mesurés sur le mini-EVM :
- **Rotations ρ à quatre opcodes** `shr(64, shl(r, X))` au lieu de sept
  (`or(shl(r, X), shr(64 − r, X))` demande X deux fois : DUP, SWAP, OR). Le
  prix : une copie valide perdue par tour. Les 25 lanes sont re-répliquées
  (`mul(and(x, 2⁶⁴ − 1), REP4)`, constantes gardées sur la pile pendant tout
  le corps) tous les trois tours, dans les stores de χ, et les cinq mots θ le
  sont à chaque tour, pour que le chemin θ n'emporte jamais de déchets dans
  les lanes. Une tentative avec ρ à quatre opcodes et θ à sept : re-réplication
  tous les deux tours, plus chère.
- **Complément de lanes** : les lanes 0, 5, 8, 14, 16, 20 sont stockées
  complémentées ; ce motif, point fixe du tour sur les drapeaux de complément
  trouvé par recherche exhaustive sur les 2²⁵ motifs, ramène χ de 25 NOT par
  tour à 7 (le motif XKCP de mémoire n'était pas un point fixe dans ce
  modèle). Complément à l'entrée, décomplément à la sortie.
- **Consommation en place** : dans χ (chaque lane de ligne sert trois fois)
  et dans θ (chaque parité de colonne deux fois), la dernière utilisation
  consomme l'opérande quand il est là où l'opération le prend (sommet pour
  NOT, sous le sommet pour AND/OR/XOR), sinon DUP ; ordres des sorties de χ
  et des mots θ choisis par recherche (120 + 120 ordres).
- Un suiveur de pile symbolique émet les DUP/SWAP et refuse toute profondeur
  au-delà de 16 (profondeur maximale utilisée : 13).

Par tour : 141 PUSH, 125 DUP, 76 XOR, 53 MLOAD, 29 SHL, 29 SHR, 28 AND, 28
MSTORE, 19 POP, 15 OR, 13 MUL, 10 SWAP, 7 NOT. Fireblocks : 137 PUSH, 107
DUP, 48 SWAP, 38 OR, 17 AND, 1 MUL, 8 NOT, le reste égal. Le gain net est
mince parce que l'arithmétique est au minimum des deux côtés ; ce qui reste
est de la pile.

### Non fait
- Accumuler les parités de colonnes du tour suivant pendant les stores de χ
  (−25 chargements par tour) : il faudrait cinq accumulateurs de plus sur la
  pile, 19 valeurs vives avec les mots θ et les lanes de ligne.
- Garder l'état complémenté entre les appels (interface « résidente
  complémentée », ~−130 gas par appel) : lie le sampler au motif du helper.

### Changed
- `ZKNOX_falcon8` se lie à `test/f1600_zknox.hex` et appelle la permutation
  résidente par `(st, 801)` ; `test/f1600_resident.hex` et
  `pythonref/gen_resident_helper.py` retirés (remplacés).
- La partie éponge du helper (absorption bloc par bloc avec inversion
  d'octets par lane, padding 0x1f/0x80, pression de 136 octets) est écrite
  dans le générateur ; le corps de permutation est un sous-programme appelé
  par les trois interfaces.

## [unreleased] — 2026-09-09 — huit lanes de 32 bits, Montgomery R = 2¹⁶, norme repliée dans le sampler (`ZKNOX_falcon8`)

### Measured (`forge test test/Benchmarks.t.sol`, KAT NIST, solc 0.8.30 via-IR, runs 1e6)
| Vérifieur | gas |
|---|---:|
| `ZKNOX_falcon_fused.verify` (quatre lanes, Barrett) | 726 912 |
| `ZKNOX_falcon8.verify` (huit lanes, Montgomery, norme dans le sampler, lanes résidentes) | **654 611** (−9,9 %) |

Depuis l'origine : 3 910 833 → 654 611, **5,97x**, helper résident froid.
Runtime `ZKNOX_falcon8` 19 745 octets ; 153/153 tests.

### Added
- `src/ZKNOX_NTT_falcon8.sol` (GÉNÉRÉ par `pythonref/gen_ntt8.py`, puis
  `forge fmt`) — `falconProduct8(s2, h)` : s1 = INTT(NTT(s2) ∘ h) sur 64 mots
  de HUIT lanes de 32 bits, réduction de Montgomery R = 2¹⁶ (−q⁻¹ mod R =
  12287) : `m = ((x & 0xffff)·12287) & 0xffff`, `r = (x + m·q) >> 16`. Le
  produit de correction tient dans une lane de 32 bits, là où le Barrett à
  quatre lanes a besoin de 64 bits pour x·M40 : moitié moins de
  papillons-mots dans les six couches alignées. Passes A (t = 256, 128, 64,
  lecture de s2 compact avec spread de huit champs vers huit lanes en trois
  étapes de masques), B (t = 32, 16, 8), noyau intra-mot scalaire (Barrett
  M = 21 pour revenir sous 2q, t = 4, 2, 1, produit pointwise par la clé
  compacte, inverse t = 1, 2, 4), B' (t = 8, 16, 32) et A' (t = 64, 128, 256
  avec 1/512 replié). Le noyau intra-mot est en SWAR sur le mot packé, sans
  variable de lane : t = 4, 2, 1 (biais 2q, 2q, 3q), Barrett, produit
  pointwise par les huit champs de la clé en un seul REDC (les valeurs
  portent alors un facteur R⁻¹, annulé par les constantes de la dernière
  couche : sommes × 7510 = 128R mod q, différences × 10323 = inv[1]·128R
  mod q), inverse t = 1, 2 (biais 5q, 10q), Barrett, t = 4 (2q). Biais aller
  alignés 2q, 2q, 2q, 3q, 3q, 4q (lanes < 3q, 5q, 7q, 10q, 13q, 17q), sommes
  inverses maintenues < 4q par soustraction conditionnelle (bit de garde
  2¹⁷) à chaque couche, sortie < 3q, stockée complémentée (3q + 6144 − s1ᵢ,
  le terme que le sampler ajoute à chaque candidat). Tables de twiddles en
  octets big-endian copiées depuis le code, lues par `mload` non aligné.
  222 314 (aller + inverse à quatre lanes) → **160 066**.

  Adressage : toutes les boucles de la chaîne avancent des pointeurs de la
  taille de leur pas (mot, octet de table, demi-mot de clé) au lieu de
  recalculer une adresse depuis le compteur. Les tables aller et inverse
  sont un seul constant contigu (l'entrée inverse est 1 024 octets plus loin
  que l'entrée aller de même rang) : le noyau lit ses six twiddles et son
  demi-mot de clé par trois pointeurs, un décalage constant et un demi
  alterné ; les passes B et B' lisent leurs sept twiddles par trois
  pointeurs. −7,7 k sur le verify (662 353 → 654 611).

  Les Barrett du noyau : trois au départ, deux après examen. Celui d'avant le
  produit par la clé tombe avec un biais 2q à la couche t = 1 (lanes < 4q,
  produit par un champ de 16 bits < 2³² − 2¹⁶q, prouvé par le modèle), au
  prix de biais 5q et 10q sur l'inverse. Les deux autres sont structurels :
  après t = 2 (lanes < 28q, le produit suivant déborderait) et avant l'inverse
  t = 4 (lanes < 20q, même raison). Un REDC réduit un produit ; ramener des
  sommes lazy sous 2q reste un Barrett à un pas.

  Le premier noyau intra-mot, en scalaires avec huit variables de lane,
  coûtait 123,7 k des 183 k : trop de variables vivantes pour le placement
  de pile de via-IR. La version SWAR est à 106,9 k, encore loin des ~30 k que
  le compte d'opérations annonce ; c'est le poste à reprendre depuis
  l'assembleur produit (voir « Ce qui reste »).
- `pythonref/model_ntt8.py` — modèle du schedule, chaque REDC asserte
  x + m·q < 2³², chaque produit final < q·R, 30 tirages dont les cas saturés,
  comparé au scalaire.
- `src/ZKNOX_falcon_core8.sol` — `hashToPointNormS1(salt, msg, helper, s1)` :
  l'ordre est inversé, s1 d'abord, puis le hash-to-point accumule
  `((t + 2q + 6144 − s1ᵢ) mod q − 6144)²` à chaque candidat accepté, sans
  jamais stocker h (un `mod`, une soustraction, un carré en complément à
  deux). Les quatre candidats d'une lane sont testés d'un coup
  (`((t & 0x7fff) + 0x0ffb) & t & 0x8000` ≠ 0 ⟺ t ≥ 5q, masques répliqués
  sur 64 bits) ; quand les quatre passent et qu'il reste quatre places, une
  seule branche et une seule lecture des quatre lanes de s1 (deux mots si
  elles chevauchent). `falcon_core8` : range check de s2 puis norme
  ‖s2‖² + ‖h − s1‖² ≤ sigBound. `ZKNOX_falcon8` : même API, même liaison de
  helper.
- `test/ntt8.t.sol` (4) : différentiel du produit contre les transformées à
  quatre lanes, lanes < 2q assertées, fuzz 256, saturés, clé hors plage ;
  `test/falcon8.t.sol` (7) : norme repliée contre le hash étendu et la norme
  scalaire (fuzz 256), décision de `falcon_core8` contre `falcon_core`, KAT
  (altérations refusées), longueurs, liaison ; bench « Verify NIST 8-LANE ».

### Correction d'ADR-004
« Montgomery ne vaut rien à q = 12289 » était vrai à quatre lanes de 64 bits
seulement : avec R = 2¹⁶ le REDC est local à une lane de 32 bits, et c'est ce
qui permet huit lanes par mot.

- **Lanes répliquées résidentes.** Le corps de permutation du helper
  travaille sur des mots où chaque lane de 64 bits est copiée quatre fois ;
  l'interface propre réplique à l'entrée et masque à la sortie, à chaque
  appel. `ZKNOX_falcon8` garde la forme répliquée entre les appels :
  absorption par XOR de lanes répliquées (× 0x0001…0001) dans l'état nul,
  permutation par l'interface de 832 octets (un mot de préfixe ignoré + 25
  mots répliqués, 25 mots répliqués en retour), sampler qui lit la copie
  basse (ses masques de byte-swap ont 64 bits, les trois autres copies
  tombent). Le wrapper résident `test/f1600_resident.hex` (19 417 octets,
  code hash `0x3926a288…8fb21337` épinglé par le constructeur) est GÉNÉRÉ par
  `pythonref/gen_resident_helper.py` autour du corps de permutation
  Fireblocks inchangé (extrait de `f1600_170.hex`, vérifié en ligne droite,
  sans accès au calldata ni au code ; état en 0x320..0x620, mode en 0x640) :
  dispatch sur la taille du calldata, 800 octets = interface propre
  d'origine (réplication à l'entrée, masque à la sortie), 832 = résidente,
  toute autre taille revert. Testé contre le helper d'origine par les deux
  interfaces sur 16 états aléatoires, les 25 lanes. Le helper propre reste
  celui de `fused` et `turbo`. −5,3 k à helper égal.

### Non repris (mesuré ou évalué)
- Norme de s2 sur huit lanes de 32 bits (A·rev(A)) : compté plus cher que
  notre version à seize champs de 16 bits (11,7 k), gardée.
- Premier essai de lecture groupée des lanes de s1 limité aux lots alignés
  (i mod 8 ≤ 4) : +12 k, le repli par candidat après un rejet reste
  désaligné longtemps ; la version à deux mots l'a remplacé (−10 k).

### Le noyau intra-mot, lu dans le bytecode
Le corps de boucle compilé (désassemblage de `out/ZKNOX_falcon8.sol/
ZKNOX_falcon8.json`, la boucle repérée par ses trois multiplications par 21)
fait **520 opcodes par mot, 1 647 gas estimés, 105 k sur 64 mots** : 42 MUL
(22 produits par twiddle ou par la clé, 14 dans les sept REDC, 6 dans les
trois Barrett), 71 AND, 35 SHR, 35 ADD, 24 OR, 8 MLOAD, aucun store
intermédiaire, aucune constante recopiée. Pas de gras de compilation : c'est
le coût de la formulation SWAR elle-même, où chaque opération Yul en vaut
~2,5 en opcodes (masques, DUP, SWAP). Le « ~30 k » annoncé comptait les
opérations Yul, pas les opcodes ; le plancher de cette formulation est ~100 k,
et les 22 multiplications sont incompressibles (huit pour le produit par la
clé, quatorze pour six couches de papillons sur huit lanes). Déplacer le
Barrett d'entrée après t = 2 (biais 5q, 6q) est neutre au gas près, gardé
parce que le schedule est plus lâche.

### Ce qui reste
- Le sampler à norme repliée : ~40 k de glue hors permutations. Repris :
  lanes de s1 complémentées à la source, les quatre candidats d'un lot
  étalés à 32 bits et ajoutés aux quatre lanes en une addition, chemin sans
  tests de borne pour les blocs qui ne peuvent pas atteindre 512 (départ
  < 445). −6 k sur le verify (671 313 → 665 118). Ce qui reste est par
  lane (byte-swap, test d'acceptation, lecture et étalement d'un lot, ~60
  opérations) et par coefficient (`mod`, centrage, carré, ~6) ; les
  variantes SWAR essayées sur papier (Barrett à quatre lanes plus
  correction, carrés par A·rev(A)) comptent à égalité, non faites.
  Plancher estimé ~35 k.
- Les permutations : le corps Fireblocks est au minimum arithmétique de
  Keccak-f (200 opérations par tour pour 206 théoriques, complément de
  lanes compris) ; 54 % de son coût est la machine à pile (156 accès mémoire
  et 154 DUP/SWAP par tour). Un générateur Keccak-f à ordonnancement
  optimisé vaudrait 10 à 15 %, c'est un projet ; le precompile (EIP-8052)
  est la vraie issue.
- Les permutations, 418 k, 62 % du total.

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
