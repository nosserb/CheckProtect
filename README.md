# CheckProtect

CheckProtect est un scanner anti-arnaque web qui aide à évaluer rapidement un message, une URL, un e-mail ou un numéro suspect.

Le projet combine :
- une analyse locale (patterns phishing/smishing),
- une vérification de réputation URL (proxy PhishStats),
- des recommandations concrètes (ne pas cliquer, signaler, contacter les canaux officiels).

## Aperçu

- **Page d'accueil** : analyse de texte + score de risque + explications.
- **Page À propos** : mission, fonctionnement, limites, sources fiables.
- **Page Signaler** : guide complet et plateformes de signalement.

## Fonctionnalités

- Détection de signaux textuels : urgence, pression, faux scénarios bancaires, usurpation.
- Détection e-mail : domaines suspects, incohérences marque/domaine, domaines jetables.
- Détection URL avancée :
	- redirections imbriquées,
	- paramètres sensibles (`return_url`, `redirect`, `token`, etc.),
	- tokens longs/haute entropie,
	- IP dans l’URL,
	- sous-domaines générés et plateformes fréquemment abusées.
- Intégration PhishStats via endpoint local : `GET /api/phishstats?host=<domain>`.
- UI dark + particules de fond discrètes.

## Stack technique

- **Frontend** : HTML, CSS, JavaScript (vanilla)
- **Backend** : Go (`net/http`)
- **API externe** : `https://api.phishstats.info/api/phishing` (via proxy serveur)

## Installation et lancement

### Prérequis

- Go 1.20+ (ou version compatible)

### Lancer localement

Depuis le dossier `server` :

```bash
cd server
go run main.go
```

Serveur par défaut :

- `http://localhost:2525`

Port personnalisé :

```bash
PORT=2526 go run main.go
```

## Endpoints

- `GET /` : sert les fichiers statiques du projet
- `GET /api/phishstats?host=example.com` : proxy vers PhishStats

## Sources et fiabilité

Les patterns de détection s’appuient sur des tendances observées et des sources reconnues :

- `phishstats.info`
- `signal-spam.fr`
- `cybermalveillance.gouv.fr`

> Le score est un **indicateur d’aide à la décision** et ne remplace pas une analyse forensique complète.

## Limites actuelles

- Heuristiques basées sur règles (pas de modèle ML supervisé).
- Risque de faux positifs/faux négatifs sur cas limites.
- Dépendance partielle à la disponibilité de l’API externe.

## Roadmap (idées)

- Historique local des analyses.
- Export des signalements (format JSON/CSV).
- Classification par “famille de campagne” plus explicite.
- Internationalisation (FR/EN).

## Contribution

Les contributions sont bienvenues :

1. Fork du projet
2. Création d’une branche feature
3. Commit clair
4. Pull request avec description des changements

## Licence

Aucune licence explicite n’est encore définie dans ce dépôt.

