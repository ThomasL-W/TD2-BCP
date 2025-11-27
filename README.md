# TD2-BCP
TD2 du cours Blockchain Programming : implémentation BIP39/BIP32.
Présentation du projet

Ce projet constitue le TD2 du module Blockchain, et porte sur l’implémentation des standards BIP39 et BIP32 utilisés pour la génération et la dérivation de clés cryptographiques dans des portefeuilles HD (Hierarchical Deterministic).

Tu y trouveras :

- Génération d’une seed BIP39

- Génération d’une phrase mnémonique

- Vérification d’une phrase mnémonique importée

- Extraction d’une master private key (xprv)

- Génération d’une master public key

- Génération de child keys (dérivation BIP32)

- Dérivation via un chemin multi-niveaux (ex : m/0/1)

L’objectif du TD est d’implémenter soi-même les mécanismes cryptographiques essentiels, sans utiliser de bibliothèques Bitcoin préconstruites, seulement des briques cryptographiques basiques (HMAC, SHA256, ECDSA).

## Partie 1 – BIP39
Objectifs demandés dans le TD :

- Générer un entier aléatoire pour l’entropie

- Le convertir en binaire / bytes / hex

- Diviser en lots de 11 bits

- Associer chaque lot à un mot du wordlist BIP39

- Afficher la phrase mnémonique complète

- Permettre l’import d’une phrase and vérifier son checksum

- Vérifier la seed sur iancoleman.io/bip39

✔️ Ce que le programme fait :

- Génère l’entropie (128–256 bits)

- Calcule le checksum

- Construit la phrase BIP39 mot par mot

- Convertit en Seed BIP39 (512 bits) via PBKDF2-HMAC-SHA512

- Permet d’importer une phrase et valide son integrité

## Partie 2 – BIP32

Objectifs demandés :

- Extraire master private key et chain code

- En déduire la master public key

- Générer une child key pour un index N

- Générer une child key pour un chemin m/i0/i1/...

✔️ Ce que le programme fait exactement :

- Utilise la seed BIP39 pour générer :

    - master private key (xprv)

    - master chain code

- Permet de dériver :

    - la clé enfant Child[0]

    - la clé enfant Child[N] (N donné par l’utilisateur)

    - une clé enfant à un chemin complet m/i0/i1/..
