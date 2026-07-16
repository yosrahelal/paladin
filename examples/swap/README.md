# Example: Atomic Swap

This example demonstrates an atomic swap of a ZKP asset for a private asset, using a custom Atom (atomic transaction) contract. Zeto is used for the ZKP asset, and Noto for the private asset, with Pente for the private logic.

See the [tutorial](https://LFDT-Paladin.github.io/paladin/head/tutorials/atomic-swap/) for a detailed explanation.

## Description du scénario

L'exemple met en scène un échange atomique entre deux investisseurs, coordonné par un contrat public `Atom` :

- `investor1` détient un actif privé Noto (`NOTO`) émis par `assetIssuer`.
- `investor2` détient du cash Zeto anonyme (`Zeto_Anon`) émis par `cashIssuer`.
- `investor1` veut vendre `100` unités d'actif à `investor2`.
- `investor2` paie `10` unités de cash à `investor1`.

Le contrat `Atom` reçoit deux appels déjà préparés : le déverrouillage/transfert de l'actif Noto vers `investor2` et le transfert du cash Zeto verrouillé vers `investor1`. Après délégation des deux verrous à l'adresse de l'Atom, l'appel `execute()` exécute les deux jambes dans une seule transaction publique. Si une jambe échoue, la transaction atomique échoue et l'échange n'est pas partiellement appliqué.

## Déroulement

1. Initialisation de trois clients Paladin et des verifiers `cashIssuer`, `assetIssuer`, `investor1` et `investor2`.
2. Déploiement de la factory `AtomFactory` sur le ledger public.
3. Déploiement du token cash Zeto.
4. Création d'un groupe privé Pente pour `assetIssuer`, puis déploiement du tracker privé ERC-20 utilisé comme hook Noto.
5. Déploiement du token actif Noto configuré en mode notary hooks avec le groupe Pente.
6. Mint initial : `1000` unités d'actif à `investor1` et `10000` unités de cash à `investor2`.
7. Verrouillage des `100` unités d'actif par `investor1`, puis préparation de l'appel de déverrouillage vers `investor2`.
8. Verrouillage des `10` unités de cash par `investor2`, puis préparation du transfert Zeto verrouillé vers `investor1`.
9. Création d'un contrat `Atom` contenant les deux opérations préparées.
10. Délégation du verrou Noto et du verrou Zeto à l'adresse de l'Atom.
11. Exécution de l'Atom, puis vérification des soldes finaux et sauvegarde des données de contrat dans le cache de l'exemple.

## Schéma

```mermaid
sequenceDiagram
    autonumber
    participant CI as cashIssuer<br/>node 1
    participant AI as assetIssuer<br/>node 1
    participant I1 as investor1<br/>node 2
    participant I2 as investor2<br/>node 3
    participant Z as Zeto cash<br/>Zeto_Anon
    participant N as Noto asset<br/>NOTO
    participant P as Pente group<br/>private tracker
    participant AF as AtomFactory
    participant A as Atom

    CI->>AF: Deploy AtomFactory
    CI->>Z: Deploy Zeto cash
    AI->>P: Create issuer privacy group<br/>deploy tracker
    AI->>N: Deploy Noto asset<br/>with Pente hook
    AI->>N: Mint 1000 NOTO to investor1
    CI->>Z: Mint 10000 cash to investor2

    I1->>N: Lock 100 NOTO
    I1->>N: Prepare unlock to investor2
    I2->>Z: Lock 10 cash
    I2->>Z: Prepare transferLocked to investor1

    CI->>AF: Create Atom with<br/>Noto unlock + Zeto transfer
    AF-->>A: Deploy Atom
    I1->>N: Delegate Noto lock to Atom
    I2->>Z: Delegate Zeto lock to Atom
    I2->>A: execute()
    A->>N: Unlock / transfer 100 NOTO to investor2
    A->>Z: transferLocked 10 cash to investor1

    N-->>I1: Final asset balance updated
    N-->>I2: Final asset balance updated
    Z-->>I1: Final cash balance updated
    Z-->>I2: Final cash balance updated
```

## Pre-requisites

Run the common [setup steps](../README.md) before running the example.

## Running the example

```shell
npm install           # install dependencies
npm run copy-abi      # copy relevant ABIs
npm run start         # run the example
```
