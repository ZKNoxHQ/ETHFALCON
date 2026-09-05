# DECISIONS.md — ADR

## ADR-001 — Sortir Keccak-f[1600] du bytecode du vérifieur

**Statut** : proposé (branche de mesure)

**Contexte**
`hashToPointNIST` représente 2 183 809 gas sur les 3 910 833 d'un
`ZKNOX_falcon.verify`, soit 55,8 %. La permutation est écrite en Solidity pur
(`src/ZKNOX_shake.sol`, `f1600(uint64[25])`) : boucle sur un tableau mémoire,
rotations 64 bits reconstruites par shift/shift/or/masque, état recopié
octet par octet dans un `uint8[200]` à chaque squeeze. Mesurée ici : 167 646 gas
par permutation.

**Décision**
Déporter la permutation dans un contrat externe dédié, appelé en `STATICCALL`,
dont le runtime est la permutation 24 tours entièrement déroulée avec constantes
en immédiats et lanes à offsets fixes. Réutiliser l'artefact `f1600_170.hex` de
fireblocks-labs/evm-ml-dsa-verifier (MIT) plutôt que de le régénérer. Conserver
l'échantillonneur par rejet à l'identique pour que le delta mesuré soit celui de
la SHAKE et de rien d'autre.

**Conséquences**

*Positives* — 41 743 gas par permutation (4,02x). Le vérifieur NIST passe sous
2 M de gas, à 1,27x du variant non conforme `ZKNOX_ethfalcon` (1 547 336) contre
2,53x avant. Le bytecode du vérifieur ne grossit pas : la permutation déroulée
(~21 Ko) dépasserait EIP-170 si elle était inlinée, c'est précisément pourquoi
elle vit dans un contrat séparé.

*Négatives et risques* —
1. Dépendance de déploiement : un helper doit exister sur la chaîne
   (~4,32 M de gas, une fois, partagé). **Résolu** — voir ADR-002.
2. `f1600_core.hex` n'est reproductible depuis aucune source publiée — le
   générateur n'a pas été conservé. Seul `f1600_170.hex` est rebuildable à partir
   de lui. La confiance repose sur du différentiel (lib-keccak, 251 KAT SHAKE) et
   sur un SHA-256 épinglé, pas sur une provenance. Réintégrer cet artefact dans
   ETHFALCON déplacerait ce trou de provenance chez nous.
3. `verify` devient `view` au lieu de `pure`.
4. Chaque permutation est un `STATICCALL` : 2 600 gas au premier appel (adresse
   froide), 100 ensuite. Compté dans les chiffres ci-dessus.

**Alternatives écartées**
- Régénérer notre propre permutation déroulée : même gain attendu, mais coût de
  développement et de validation non nul pour un artefact déjà testé en amont.
  À reconsidérer précisément à cause du point 2.
- Garder Solidity et optimiser les rotations (représentation quadruplée des lanes,
  suppression des masques) : environ -4 200 gas/permutation d'après l'amont, très
  loin des -125 900 obtenus ici, parce que l'essentiel du surcoût est la boucle et
  le marshalling `uint8[200]`, pas la rotation.
- Basculer sur `ZKNOX_ethfalcon` (hash-to-point keccak, 94 077 gas) : moins cher
  mais non conforme NIST. Orthogonal : cet ADR sert les cas où la conformité
  FIPS est exigée.

**Répartition du gain** (1 648 742 gas économisés sur `hashToPointNIST`)
8 permutations sont nécessaires pour 512 coefficients (1 078 octets consommés,
8 blocs de rate). 8 x 125 903 = 1 007 224, soit 61 % du gain venant de la
permutation elle-même. Les 39 % restants (~641 k) viennent de la plomberie de
l'éponge : absorb/squeeze par mots de 32 octets avec inversion d'octets en
registre, au lieu du tampon `uint8[200]` parcouru octet par octet.


## ADR-002 — Lier le helper par EXTCODEHASH, pas par adresse

**Statut** : appliqué

**Contexte**
ADR-001 déporte Keccak-f[1600] dans un contrat externe. Le résultat d'une
vérification dépend donc du code présent à une adresse que le vérifieur ne
contient pas. La première version ne contrôlait que `helper.code.length != 0`,
au constructeur seulement. N'importe quel contrat passe ce test.

**Menace**
Un helper qui répond bien mais faux — bonne taille de retour, jamais de revert,
donc invisible pour les contrôles de vivacité de `f1600Fast170` — met la sortie
de SHAKE256 sous contrôle de son auteur, donc le point rendu par
`hashToPointNIST`, donc l'entrée de `falcon_core`. Le cas limite est mesuré dans
`test/falcon_fast_helper.t.sol` : avec un helper renvoyant un état constant, deux
couples (salt, message) distincts hachent vers le MÊME polynôme. Le message ne lie
plus rien. Un seul `s2` de norme courte trouvé une fois vaut alors pour tout
message et toute clé publique. Le choix du helper appartenant au déployeur du
vérifieur, c'est une hypothèse de confiance que `ZKNOX_falcon` n'avait pas.

**Décision**
Épingler `F1600_CODEHASH` en constante dans le vérifieur, contrôler
`helper.codehash` au constructeur et le re-contrôler au début de chaque `verify`.

**Conséquences**
- La liaison est lisible dans le source du vérifieur : personne n'a besoin de
  faire confiance au déployeur ni d'auditer une adresse à part.
- Liaison par contenu, donc helper fongible : un seul déploiement sert tous les
  vérifieurs de la chaîne, quelle que soit son adresse.
- Coût : +129 gas par `verify` (1 962 660 -> 1 962 789). `EXTCODEHASH` est le
  premier accès au compte, il absorbe les 2 600 gas de compte froid que le
  premier `STATICCALL` payait de toute façon.
- +144 octets de runtime (7 966 -> 8 110), soit 16 466 de marge EIP-170.

**Pourquoi aussi à chaque appel, et pas seulement au constructeur**
Depuis EIP-6780 (Cancun), `SELFDESTRUCT` ne supprime plus un compte hors de sa
transaction de création, donc le code d'une adresse est en pratique immuable et
un contrôle unique suffirait presque. « Presque » n'est pas un argument de
sécurité pour un coût nul. `test_per_call_recheck_catches_a_swapped_helper`
montre le contrôle attrapant une substitution post-construction.

**Ce que ceci ne règle pas**
Que le bytecode épinglé calcule bien Keccak-f[1600]. Le hash garantit qu'on
appelle *ce* bytecode-là, pas qu'il soit correct. Cette correction-là repose sur
le différentiel amont (lib-keccak, 251 KAT SHAKE) et reste sans provenance
reproductible (ADR-001, point 2).

## ADR-003 — Fusion radix-8 de la NTT, sampler Yul, normes SWAR : un vérifieur séparé, additif

**Contexte**
Après la SHAKE externe (ADR-001/002) et la NTT packée, `ZKNOX_falcon_turbo`
coûtait 1 327 039 gas : 535 k de hash-to-point (dont 334 k de permutations
incompressibles et ~200 k de glue Solidity du sampler), ~750 k de `falcon_core`
(NTT 190 k + INTT 252 k + normalize 171 k + pack/unpack ~80 k). Le déroulage et
via-IR avaient été mesurés à 3-10 % et écartés. Le levier réel du vérifieur
ML-DSA de fireblocks n'est pas le déroulage mais la fusion de couches : un
octet de mots chargé une fois pour trois couches.

**Décision**
1. Nouvelle transformée `ZKNOX_NTT_falcon_fused.sol`, générée, en six passes
   radix-8 (A, B, C / C', B', A'), avec le décodage compact -> lanes replié
   dans les loads de A, le produit pointwise par la clé compacte replié dans
   C', n^-1 replié dans A', sortie canonique. Le schedule est validé d'abord en
   Python (modèle avec assertions de bornes), puis en Solidity par différentiel
   contre la transformée packée (elle-même assertée contre la référence).
2. Échantillonneur hash-to-point en Yul lisant l'état de l'éponge, sortie
   packée. Même fonction mathématique, assertée égale sur le KAT et par fuzz.
3. Normes en SWAR 16 bits (`E * rev(E)`), range check en premier.
4. Un vérifieur SÉPARÉ `ZKNOX_falcon_fused` (même API, même liaison de helper)
   plutôt qu'une modification de `ZKNOX_falcon_turbo` : les trois versions
   (référence, turbo, fused) restent mesurables et différentiables dans un même
   run, et un audit peut lire la version lente comme spécification.
5. Le fichier Solidity de la transformée est un ARTEFACT GÉNÉRÉ (en-tête
   explicite, commande de régénération, `forge fmt` ensuite). Les corps
   radix-8 et les passes intra-mot déroulées ×4 sont répétitifs, et leur
   validité dépend de la discipline de pile du codegen legacy (≤ 16 slots
   atteignables, aucun spill) : une source unique évite qu'une correction sur
   l'une des six passes ne diverge des cinq autres.

**Conséquences**
- 755 683 gas par `verify` (1,76x vs turbo, 5,17x vs l'origine). Le helper
  Keccak-f (418 k pour 10 permutations sur le KAT) est désormais 55 % du coût
  et le plancher tant qu'on garde SHAKE256.
- Runtime 19 342 octets (marge EIP-170 5 234). Le déroulage ×4 et les
  constantes de 32 octets sont le prix des passes intra-mot sans curseur ; les
  passes radix-8 elles-mêmes sont compactes.
- Bornes lazy explicites (aller < 19q, inverse < 128q avant la dernière
  couche, produits < 2^31, Barrett < 2^58) documentées en tête de fichier et
  exercées par les vecteurs saturés. Toute modification du schedule doit
  passer par le modèle Python avant le générateur.
- La sécurité du verify ne change pas : mêmes contrôles de longueur, même
  range check sur s2 (fait AVANT la transformée, car le spread suppose des
  champs de 15 bits), même borne, même liaison du helper. La clé publique est
  consommée par `mulmod` sur ses champs de 16 bits, comme dans
  `_ZKNOX_NTT_HALFMUL_Compact` : un champ ≥ q est réduit mod q dans les deux
  versions.

**Ce qui a été mesuré et refusé**
Intra-mot inverse en SWAR (139 709 vs 131 149), intra-mot aller en scalaires
(130 206 vs 119 454), intra-mot avec curseurs et fonctions Yul (72 674 /
86 450 vs 52 908 / 75 201). Détail dans VERSION.md.

**Ce que ceci ne règle pas**
Le coût des permutations Keccak-f. Les ~30 k du sampler et les ~25 k de glue
sont les seules marges restantes hors NTT ; la NTT fusionnée est à ~130 gas par
papillon-mot pour ses passes alignées, proche du plancher du modèle 4×64.

## ADR-004 — Profil de compilation : solc 0.8.30, via-IR, `optimizer_runs = 1000000`

**Contexte**
Le vérifieur fusionné est fait de noyaux SWAR en assembleur avec des
constantes de 32 octets répétées ; leur coût dépend du codegen et de
l'optimiseur de constantes autant que de l'arithmétique (ETHDILITHIUM,
ADR-004). Le dépôt était en solc 0.8.25, legacy, runs 10000, et via-IR y
avait été écarté au début du chantier sur la NTT scalaire.

**Décision**
Profil `default` et `ci` en solc 0.8.30, via-IR, runs 1e6. Mesuré :
`ZKNOX_falcon_fused` 755 683 → 726 898, core 282 k → 250 k, sans changer
une ligne de Solidity. solc 0.8.25 ne sait pas placer la pile des passes
fusionnées sous via-IR ; 0.8.30 oui.

**Conséquences**
- 5,38x depuis l'origine. Le bytecode déployé change pour tous les contrats,
  y compris ceux qui ne sont pas des produits (référence scalaire +2,9 %).
- Règle : un noyau SWAR se mesure dans le contrat final sous le profil
  livré, et `grep codecopy` sur `forge inspect <contrat> asm` fait partie de
  la revue.
- Ce qui reste : 10 permutations Keccak-f pour le hash-to-point sur ce KAT,
  418 k, 58 % du total, plancher du Falcon NIST avec ce helper.
