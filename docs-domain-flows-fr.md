# Flux techniques des domains Pente, Noto et Zeto

## Vue d’ensemble : le flux commun Paladin

Techniquement, **Pente**, **Noto** et **Zeto** sont trois *domains* Paladin différents, mais ils s’insèrent dans le même pipeline d’orchestration de transaction privée :

1. **Le client / SDK / JSON-RPC soumet une intention de transaction** au nœud Paladin.
2. **Paladin appelle le domain** concerné avec une suite d’étapes :
   - `InitTransaction`
   - `AssembleTransaction`
   - collecte des signatures / attestations / endorsements
   - `PrepareTransaction`
3. Le domain retourne une **`PreparedTransaction`**, soit :
   - `PUBLIC` : transaction destinée directement au L1 ;
   - `PRIVATE` : transaction privée chaînée vers un autre domain / privacy group.
4. Paladin encode l’appel ABI, choisit le signer / submitter, construit une transaction Ethereum, la signe, puis l’envoie au L1 via `eth_sendRawTransaction`.

Dans le testbed, on voit explicitement cette séquence : `InitTransaction`, résolution des verifiers, `AssembleTransaction`, écriture des états potentiels, collecte des signatures, endorsements, résolution du signer, puis `PrepareTransaction`. 【F:core/go/pkg/testbed/testbed_jsonrpc_actions.go†L281-L344】

---

## 1. Pente : private EVM / “Tessera++”

### Rôle fonctionnel

**Pente** est un domain Java qui fournit une capacité de **private EVM** : on exécute des transactions EVM dans un état privé partagé par les membres d’un privacy group. Le README le décrit comme un domain Java fournissant des capacités de private EVM “Tessera++”. 【F:domains/pente/README.md†L1-L5】

Concrètement, Pente permet de :

- créer un **privacy group** ;
- déployer des smart contracts privés dans ce groupe ;
- invoquer des fonctions privées ;
- faire valider les transitions d’état par les membres du groupe ;
- ancrer la transition sur le L1 via le contrat `PentePrivacyGroup.transition(...)`.

### Composants qui interagissent

Les composants principaux sont :

- **Client / SDK Paladin**
  - demande la création d’un groupe ou l’exécution d’une transaction EVM privée.
- **Paladin core**
  - orchestre la transaction privée ;
  - appelle le plugin/domain Pente ;
  - résout les identités / verifiers ;
  - collecte les endorsements ;
  - prépare puis soumet la transaction L1.
- **Pente domain Java**
  - implémente `prepareDeploy`, `initTransaction`, `assembleTransaction`, `endorseTransaction`, `prepareTransaction`, et `wrapPrivacyGroupTransaction`.
- **EVMRunner / PenteEVMTransaction**
  - exécute localement l’EVM sur l’état privé.
- **State store Paladin**
  - contient les comptes / états privés sérialisés.
- **Endorsers du privacy group**
  - rejouent l’exécution et signent si les outputs correspondent.
- **Contrats L1**
  - `PenteFactory`
  - `PentePrivacyGroup`
- **Key manager**
  - signe les attestations et la transaction Ethereum finale.
- **L1 RPC endpoint**
  - reçoit la transaction via `eth_sendRawTransaction`.

### Flux de création d’un privacy group

Lors d’un déploiement Pente, `prepareDeploy` lit les paramètres de constructeur, résout les endorsers à partir du `salt` et des `members`, construit la configuration on-chain, puis prépare un appel ABI à `newPrivacyGroup`. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L156-L184】

Ensuite, au moment où Paladin initialise le contrat Pente, `initContract` configure le contrat comme suit :

- `CoordinatorSelection = COORDINATOR_ENDORSER`
- `SubmitterSelection = SUBMITTER_COORDINATOR`
- les candidats coordinateur/endorser sont dérivés des membres du privacy group. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L190-L210】

Donc, pour Pente, le submitter L1 est typiquement **le coordinateur** du privacy group, pas forcément l’utilisateur initial.

### Flux d’une transaction Pente

#### Étape 1 — `InitTransaction`

Pente commence par demander la résolution du signer ECDSA / Ethereum address correspondant au `from` de la transaction. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L223-L233】

#### Étape 2 — `AssembleTransaction`

Pendant `AssembleTransaction`, Pente :

1. construit un `PenteTransaction` ;
2. charge dynamiquement l’état privé ;
3. exécute la transaction dans l’EVM via `PenteEVMTransaction.invokeEVM(...)` ;
4. produit les nouveaux états privés ;
5. ajoute un état `info` contenant la transaction raw signée nécessaire aux endorsers ;
6. construit un `AttestationPlan` demandant des endorsements à tous les membres du groupe. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L287-L326】

Le point clé : Pente exécute réellement la transaction EVM **avant** qu’elle n’aille sur le L1. Le L1 ne reçoit pas une transaction EVM privée complète ; il reçoit une transition d’état privée validée.

#### Étape 3 — `EndorseTransaction`

Chaque endorser :

1. recharge les inputs / reads ;
2. récupère la transaction depuis l’état `info` ;
3. rejoue localement l’EVM ;
4. compare les outputs calculés avec les outputs proposés ;
5. signe un payload EIP-712 si tout correspond. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L362-L440】

C’est le mécanisme d’intégrité : les membres ne signent que si leur exécution locale produit exactement la même transition d’état.

#### Étape 4 — `PrepareTransaction`

Une fois les endorsements collectés, Pente prépare l’appel L1 au contrat privacy group. Il collecte les signatures d’endorsement, les IDs d’états inputs / reads / outputs / info, les external calls, puis construit un appel ABI à la fonction `transition`. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L455-L491】

Si l’intention est une vraie transaction à soumettre, Pente force le signer requis sur le `from` de la transaction. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L494-L505】

### Flux spécifique `wrapPrivacyGroupTransaction`

Pente expose aussi un wrapper pour transformer une transaction EVM privée classique — deploy, invoke, transfer — en une `PreparedTransaction` de type `PRIVATE`. La méthode ajoute les données du groupe, le `to`, le bytecode, les inputs ABI, le gas et la value si nécessaire. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L771-L895】

### Comment la transaction Pente arrive au L1 ?

Le L1 ne voit pas le contenu privé complet. Il voit principalement :

- l’appel au contrat `PentePrivacyGroup.transition(...)` ;
- les IDs d’états consommés / produits ;
- les signatures d’endorsement ;
- éventuellement des external calls déclarés.

Paladin reçoit la `PreparedTransaction`, l’encode, la signe, puis la soumet au L1 comme une transaction Ethereum normale.

---

## 2. Noto : token notarized confidentiel

### Rôle fonctionnel

**Noto** est un domain Go pour des **tokens confidentiels notarized**, contrôlés par une partie de confiance : le **notary**. Le README le décrit comme un domain Go fournissant des tokens notarized confidentiels contrôlés par une trusted party. 【F:domains/noto/README.md†L1-L5】

Noto est donc différent de Pente :

- Pente = private EVM avec endorsements des membres du groupe.
- Noto = token UTXO confidentiel avec un **notaire coordinateur** qui valide et soumet.

### Composants qui interagissent

Les composants principaux sont :

- **Client / SDK**
  - demande `mint`, `transfer`, `burn`, `lock`, `unlock`, etc.
- **Paladin core**
  - orchestre init / assemble / endorse / prepare.
- **Noto domain Go**
  - valide les paramètres ;
  - sélectionne les inputs UTXO ;
  - prépare les outputs ;
  - construit les attestations ;
  - prépare l’appel L1.
- **Notary**
  - coordinateur statique ;
  - endorser ;
  - submitter.
- **Participants**
  - sender, owner, receiver.
- **State store Paladin**
  - conserve les coins / states.
- **Contrat Noto L1**
  - exécute `transfer`, `mint`, `burn`, etc.
- **Key manager**
  - signe les attestations.
- **L1 RPC**
  - reçoit la transaction finale.

### Initialisation du contrat Noto

Lors de `InitContract`, Noto décode la configuration on-chain, identifie le notary, détermine si le nœud local est ce notary, puis configure :

- `CoordinatorSelection = COORDINATOR_STATIC`
- `StaticCoordinator = notary`
- `SubmitterSelection = SUBMITTER_COORDINATOR`

Donc pour Noto, **le notary est le coordinateur statique et le submitter L1**. 【F:domains/noto/internal/noto/noto.go†L712-L764】

### Routage des handlers

Noto délègue les étapes de transaction à des handlers selon la méthode appelée : `mint`, `transfer`, `burn`, `lock`, `unlock`, etc. On voit que `InitTransaction`, `AssembleTransaction`, `EndorseTransaction` et `PrepareTransaction` valident la transaction puis appellent le handler correspondant. 【F:domains/noto/internal/noto/noto.go†L767-L793】

### Exemple : flux `transfer`

#### Étape 1 — `InitTransaction`

Pour un transfer, Noto demande la résolution des verifiers Ethereum du notary, du sender, du `from` et du `to`. 【F:domains/noto/internal/noto/handler_transfer_common.go†L45-L51】

#### Étape 2 — `AssembleTransaction`

Pendant l’assemblage, Noto :

1. résout les identités ;
2. sélectionne les input states / coins disponibles ;
3. prépare les output states pour le destinataire ;
4. crée éventuellement un output de rendu de monnaie pour le sender ;
5. prépare les info states ;
6. encode le transfert non masqué pour signature ;
7. construit le `AttestationPlan` demandant l’endorsement du notary. 【F:domains/noto/internal/noto/handler_transfer_common.go†L54-L140】

Pour les variants avec nullifiers, Noto ajoute aussi des `NullifierSpec` sur les nouveaux outputs afin que les futurs spends puissent être prouvés / consommés sans révéler directement l’input. 【F:domains/noto/internal/noto/handler_transfer_common.go†L74-L84】

#### Étape 3 — `EndorseTransaction`

Le notary :

1. parse les inputs et outputs ;
2. vérifie la conservation des montants ;
3. vérifie que le sender possède les inputs ;
4. vérifie la signature du sender ;
5. retourne `ENDORSER_SUBMIT`.

Ce dernier point est crucial : le notary ne fait pas juste signer ; il impose que **l’endorser soumette** la transaction. 【F:domains/noto/internal/noto/handler_transfer_common.go†L143-L171】

#### Étape 4 — `PrepareTransaction`

Pour préparer l’appel L1, Noto :

1. vérifie que l’endorsement du notary est présent ;
2. encode les transaction data ;
3. récupère la signature sender ;
4. encode les inputs / outputs / preuve ;
5. prépare l’appel ABI `transfer(...)`.

【F:domains/noto/internal/noto/handler_transfer_common.go†L276-L297】 【F:domains/noto/internal/noto/handler_transfer_common.go†L174-L227】

La `TransactionWrapper.prepare()` convertit ensuite l’ABI + params en `PrepareTransactionResponse` contenant une `PreparedTransaction`. 【F:domains/noto/internal/noto/handlers.go†L212-L225】

### Public vs private dans Noto

Noto peut retourner une transaction `PUBLIC` ou `PRIVATE` selon le type demandé. La fonction `mapPrepareTransactionType` mappe `pldapi.TransactionTypePrivate` vers `PreparedTransaction_PRIVATE`, sinon elle retourne `PreparedTransaction_PUBLIC`. 【F:domains/noto/internal/noto/noto.go†L1219-L1224】

En pratique :

- mode basique : souvent appel public au contrat Noto L1 ;
- mode hooks : possibilité d’envelopper via un autre contrat / domain privé, par exemple avec Pente.

### Comment la transaction Noto arrive au L1 ?

Dans le cas standard :

1. le client initie un transfert ;
2. Noto assemble inputs / outputs ;
3. le sender signe ;
4. le notary endorse ;
5. comme `SubmitterSelection = SUBMITTER_COORDINATOR`, le notary / coordinateur soumet ;
6. Paladin encode l’appel `transfer(...)` du contrat Noto ;
7. Paladin signe et envoie la transaction Ethereum au L1.

---

## 3. Zeto : token privacy-preserving avec ZK proofs

### Rôle fonctionnel

**Zeto** est un domain Go pour des tokens privacy-preserving basés sur Zeto / ZKP. Le README le décrit comme un domain Go fournissant des tokens privacy-preserving basés sur Zeto. 【F:domains/zeto/README.md†L1-L5】

La différence majeure avec Noto :

- Noto repose sur un **notary**.
- Zeto repose sur des **preuves zero-knowledge** générées par le sender.

### Composants qui interagissent

Les composants principaux sont :

- **Client / SDK**
  - demande `mint`, `transfer`, `deposit`, `withdraw`, etc.
- **Paladin core**
  - orchestre la transaction.
- **Zeto domain Go**
  - sélectionne les UTXOs ;
  - prépare les nouveaux coins ;
  - construit la demande de preuve ;
  - encode l’appel L1.
- **Zeto signer / prover**
  - génère une preuve SNARK / ZK.
- **BabyJubJub keys**
  - utilisées comme verifiers Zeto.
- **State store Paladin**
  - conserve les coins et arbres de Merkle.
- **Contrats Zeto L1**
  - vérifient les preuves.
- **Verifier contracts / Poseidon / SMT libs**
  - utilisés côté Solidity pour vérifier les preuves et arbres.
- **Key manager / signer**
  - signe / produit les attestations ZK.
- **L1 RPC**
  - reçoit la transaction finale.

### Initialisation du contrat Zeto

Lors de `InitContract`, Zeto décode la config du domain et configure :

- `CoordinatorSelection = COORDINATOR_SENDER`
- `SubmitterSelection = SUBMITTER_SENDER`

Donc contrairement à Noto, **le sender est coordinateur et submitter**. 【F:domains/zeto/internal/zeto/zeto.go†L284-L303】

### Routage des handlers

Comme Noto, Zeto route `InitTransaction`, `AssembleTransaction`, `EndorseTransaction` et `PrepareTransaction` vers le handler de méthode correspondant. 【F:domains/zeto/internal/zeto/zeto.go†L306-L331】

### Exemple : flux `transfer`

#### Étape 1 — `InitTransaction`

Zeto demande la résolution des verifiers BabyJubJub compressés du sender et des destinataires. 【F:domains/zeto/internal/zeto/fungible/handler_transfer.go†L112-L132】

C’est une différence importante avec Noto : ici le domain ne cherche pas des verifiers Ethereum classiques pour la logique privée, mais des clés compatibles Zeto / BabyJubJub.

#### Étape 2 — `AssembleTransaction`

Pendant l’assemblage, Zeto :

1. résout le sender BabyJubJub ;
2. sélectionne les input coins ;
3. prépare les output coins ;
4. ajoute un output de rendu de monnaie si nécessaire ;
5. prépare les info states ;
6. prépare la requête de preuve ZK ;
7. demande une attestation `SIGN` au sender avec payload type Zeto SNARK.

【F:domains/zeto/internal/zeto/fungible/handler_transfer.go†L135-L215】

La requête de preuve est construite via `formatTransferProvingRequest(...)`, avec les inputs, outputs, circuits, token name, state query context et adresse du contrat. 【F:domains/zeto/internal/zeto/fungible/handler_transfer.go†L187-L193】

#### Étape 3 — `EndorseTransaction`

Pour le handler transfer fongible, `Endorse` est vide / no-op dans ce fichier : le point critique n’est pas un endorsement notarial, mais l’attestation ZK du sender et la preuve vérifiée on-chain. 【F:domains/zeto/internal/zeto/fungible/handler_transfer.go†L217-L217】

#### Étape 4 — `PrepareTransaction`

Lors du prepare, Zeto :

1. récupère l’attestation `sender` ;
2. désérialise la `ProvingResponse` ;
3. reconstruit inputs / outputs ;
4. encode les transaction data ;
5. injecte la preuve ZK ;
6. ajoute selon le variant :
   - `ecdhPublicKey`, `encryptionNonce`, `encryptedValues` pour les tokens chiffrés ;
   - `nullifiers` et `root` pour les tokens à nullifiers ;
   - sinon les `inputs` explicites ;
7. retourne la `PreparedTransaction` avec l’ABI de `transfer`.

【F:domains/zeto/internal/zeto/fungible/handler_transfer.go†L221-L284】

### Exemple : flux `deposit`

Le `deposit` prépare lui aussi une preuve, encode les outputs et l’amount, puis retourne une transaction L1 avec `RequiredSigner = req.Transaction.From`, car le deposit doit être signé par le sender original. 【F:domains/zeto/internal/zeto/fungible/handler_deposit.go†L171-L228】

### Comment la transaction Zeto arrive au L1 ?

Le flux est :

1. le sender initie la transaction ;
2. Zeto sélectionne les UTXOs privés ;
3. Zeto demande au signer/prover une preuve SNARK ;
4. `PrepareTransaction` encode l’appel au contrat Zeto avec la preuve ;
5. comme `SubmitterSelection = SUBMITTER_SENDER`, le sender soumet ;
6. le contrat L1 vérifie la preuve et applique la transition.

---

## 4. Comment une transaction est soumise vers le L1 ?

### Étape A — le domain retourne une `PreparedTransaction`

Chaque domain finit par produire une `PreparedTransaction` contenant typiquement :

- `FunctionAbiJson`
- `ParamsJson`
- éventuellement `RequiredSigner`
- éventuellement `Type = PUBLIC` ou `PRIVATE`

Par exemple, Zeto retourne l’ABI et les params JSON dans `PrepareTransactionResponse`. 【F:domains/zeto/internal/zeto/fungible/handler_transfer.go†L277-L283】

Noto fait la même chose via `TransactionWrapper.prepare()`. 【F:domains/noto/internal/noto/handlers.go†L212-L225】

Pente construit l’appel `transition` avec ABI + params. 【F:domains/pente/src/main/java/io/kaleido/paladin/pente/domain/PenteDomain.java†L476-L491】

### Étape B — Paladin encode l’appel ABI

Le testbed montre que la transaction préparée est encodée via `EncodeCallDataJSONCtx`, à partir de l’ABI et des données préparées. 【F:core/go/pkg/testbed/testbed_jsonrpc_actions.go†L444-L459】

### Étape C — Paladin construit et signe une transaction Ethereum

Le client Ethereum Paladin construit une raw transaction :

1. résout le `from` via le key manager ;
2. récupère le nonce avec `eth_getTransactionCount` si nécessaire ;
3. estime le gas avec `eth_estimateGas` si nécessaire ;
4. construit le payload de signature selon EIP-1559 ou legacy ;
5. demande au key manager de signer ;
6. finalise la raw transaction. 【F:core/go/pkg/ethclient/client.go†L343-L415】

### Étape D — Paladin soumet au L1

La soumission réelle se fait via `eth_sendRawTransaction`. 【F:core/go/pkg/ethclient/client.go†L418-L430】

La méthode `SignAndSend()` illustre le raccourci : elle construit la raw transaction puis appelle `SendRawTransaction`. 【F:core/go/pkg/ethclient/function_client.go†L437-L442】

---

## Comparaison rapide des trois domains

| Domain | Modèle privacy | Coordinateur | Submitter L1 | Validation principale | Contrat L1 appelé |
|---|---|---:|---:|---|---|
| **Pente** | Private EVM / privacy group | Endorser du groupe | Coordinateur | Rejeu EVM + endorsements membres | `PentePrivacyGroup.transition(...)` |
| **Noto** | Token UTXO notarized | Notary statique | Coordinateur / notary | Notary vérifie ownership, montants, signature sender | Contrat Noto `transfer`, `mint`, `burn`, etc. |
| **Zeto** | Token ZK / UTXO | Sender | Sender | Preuve SNARK / ZK vérifiée on-chain | Contrat Zeto `transfer`, `deposit`, `withdraw`, etc. |

---

## Résumé mental du flux

### Pente

```text
Client
  -> Paladin
    -> Pente.InitTransaction
    -> Pente.AssembleTransaction
         -> exécution EVM privée
         -> outputs privés
         -> plan d’endorsement membres
    -> membres endorsent en rejouant l’EVM
    -> Pente.PrepareTransaction
         -> appel transition(...)
    -> Paladin signe + eth_sendRawTransaction
  -> L1 PentePrivacyGroup
```

### Noto

```text
Client
  -> Paladin
    -> Noto.InitTransaction
    -> Noto.AssembleTransaction
         -> sélection coins
         -> outputs
         -> attestation sender + notary
    -> Notary.EndorseTransaction
         -> vérifie montants + owners + signature
         -> ENDORSER_SUBMIT
    -> Noto.PrepareTransaction
         -> appel Noto transfer/mint/burn
    -> Paladin signe + eth_sendRawTransaction
  -> L1 Noto
```

### Zeto

```text
Client / Sender
  -> Paladin
    -> Zeto.InitTransaction
    -> Zeto.AssembleTransaction
         -> sélection coins
         -> outputs
         -> payload de preuve SNARK
    -> signer/prover génère la preuve
    -> Zeto.PrepareTransaction
         -> appel Zeto avec proof/root/nullifiers/outputs
    -> Paladin signe + eth_sendRawTransaction
  -> L1 Zeto verifier + token contract
```
