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
