# TP10 — DevSecOps « Shift Left »

Secrets (Gitleaks, pre-commit), SAST (Semgrep, CodeQL), SCA (npm audit, OWASP Dependency-Check, Dependabot), image et configuration (Trivy), workflow GitHub Actions sécurisé, ruleset sur `main` et quality gates Jenkins.

⚠️ `vuln-app` est une application de lab : à ne jamais exposer hors de la VM.

| Famille | Question posée | Outils |
|---|---|---|
| Secrets | Un mot de passe ou un token est-il dans Git ? | Gitleaks, hook pre-commit, push protection GitHub |
| SAST | Le code contient-il des motifs dangereux ? | Semgrep, CodeQL |
| SCA | Les dépendances ont-elles des CVE connues ? | npm audit, OWASP Dependency-Check, Dependabot |
| Image | Les paquets de l'image ont-ils des CVE ? | Trivy image |
| Config | Le Dockerfile est-il mal configuré ? | Trivy config |

## Partie 1 — Secrets avec Gitleaks

```bash
docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest git /repo --verbose
```

| Règle | Fichier:ligne | Commit | Constat |
|---|---|---|---|
| `generic-api-key` | `src/config.js:5` | import initial | `jwt_secret` codé en dur |

`config.js` contenait aussi `payment_api_key` et `db_password`, et le Dockerfile `ENV DB_PASSWORD=…` : tous ont été retirés.

**Correction :** les valeurs sont lues dans `process.env` (`JWT_SECRET`, `PAYMENT_API_KEY`, `DB_PASSWORD`), le démarrage échoue si `JWT_SECRET` manque, `.env.example` documente les variables et `.env` est dans `.gitignore`.

**Pourquoi le secret est encore détecté après correction ?** Gitleaks analyse tout l'historique : le secret reste dans le commit d'origine. Supprimer le fichier ne suffit jamais. Pour un vrai secret, il faut **le révoquer** (le considérer comme compromis), en générer un nouveau, puis éventuellement réécrire l'historique (`git filter-repo`). Pour ce lab, l'historique a été recréé proprement (`rm -rf .git && git init -b main`) et un `.gitleaksignore` vide documentera les futurs faux positifs.

![Gitleaks](captures/gitleaks.png)

## Partie 2 — Hook pre-commit

`.pre-commit-config.yaml` lance Gitleaks (v8.30.1) avant chaque commit :

```bash
pipx install pre-commit
pre-commit autoupdate && pre-commit install
```

Un commit contenant un token de test est refusé par le hook ; après suppression de la ligne, le commit passe.

![Commit refusé](captures/pre-commit-blocked.png)

## Partie 3 — SAST avec Semgrep

```bash
docker run --rm -v "$PWD:/src" semgrep/semgrep \
  semgrep scan --config p/javascript --config p/owasp-top-ten --config /src/.semgrep --error /src
```

| Règle | Fichier:ligne | Vrai positif ? | Correction |
|---|---|---|---|
| `tainted-sql-string` | `src/server.js:21` | Oui : `req.query.name` concaténé dans le SQL | Requête paramétrée `db.all("… WHERE name = ?", [name])`, erreur SQL non renvoyée au client |
| `detect-child-process` | `src/server.js:27` | Oui : `exec("ping -c 1 " + host)` passe par un shell | `execFile("ping", ["-c", "1", host])` sans shell + validation de `host` (pas de `-` initial, caractères autorisés, 253 max) |
| `raw-html-format` | `src/server.js:32` | Oui : XSS réfléchi | Réponse `res.json(...)` au lieu de HTML concaténé |
| `direct-response-write` | `src/server.js:32` | Oui : même XSS | Idem |
| `express-check-csurf-middleware-usage` | `src/server.js:10` | Faux positif dans notre contexte : API JSON sans cookie de session, le JWT est envoyé explicitement | Risque accepté : `// nosemgrep: express-check-csurf-middleware-usage` avec justification |

Corrections supplémentaires non détectées par Semgrep mais relevées à la revue :

- `jwt.sign` : algorithme `HS256` fixé et `expiresIn: "1h"`, secret lu dans l'environnement ;
- `/settings` : plus de `_.merge` d'un objet client (prototype pollution) ; seuls `theme` et `language` sont recopiés dans un objet sans prototype, lodash est supprimé des dépendances ;
- `express.json({ limit: "10kb" })` et `x-powered-by` désactivé.

Résultat après correction : **0 résultat bloquant**.

Une première version de la validation de `host` utilisait une regex avec quantificateurs imbriqués : Semgrep l'a signalée (`detect-redos`). Elle a été remplacée par une regex simple + contrôle de longueur.

![Semgrep avant / après](captures/semgrep-before-after.png)

## Partie 4 — Dépendances et images

### npm audit

| | Total | Critical | High | Low |
|---|---|---|---|---|
| Avant | 16 | 1 (`tar`) | 10 | 5 |
| Après | **0** | 0 | 0 | 0 |

Paquets directs vulnérables avant : `express 4.17.1`, `jsonwebtoken 8.5.1`, `lodash 4.17.15`, `sqlite3 5.1.7` (via `tar`, `node-gyp`, `cacache`, `make-fetch-happen`).
Après : `express ^4.22.3`, `jsonwebtoken ^9.0.3`, `sqlite3 ^6.0.1`, `lodash` supprimé (plus utilisé).

`npm audit --audit-level=high` : code retour **1** avant, **0** après.

### OWASP Dependency-Check

| | npm audit | Dependency-Check |
|---|---|---|
| Nombre de CVE (avant) | 16 | _à compléter_ |
| Mêmes CVE ? | | _à compléter_ |
| Même gravité ? | | _à compléter_ |

Dependency-Check s'appuie sur la NVD (CPE + CVSS) alors que npm audit s'appuie sur la GitHub Advisory Database : les identifiants (CVE / GHSA) et les scores peuvent différer, et Dependency-Check produit davantage de faux positifs liés aux CPE.

### Trivy

| | Trivy config (Dockerfile) | Trivy image HIGH/CRITICAL |
|---|---|---|
| Avant (`node:14`, root, `ENV DB_PASSWORD`) | 3 : DS-0031 CRITICAL (secret dans ENV), DS-0002 HIGH (root), DS-0026 LOW (pas de HEALTHCHECK) | _à compléter_ |
| Après (`node:24-alpine`, multi-stage, `USER node`) | **0** | _à compléter_ |

Dockerfile corrigé : image `node:24-alpine`, multi-stage (outils de compilation seulement dans l'étape `deps`), `npm ci --omit=dev`, npm/yarn/corepack retirés de l'image finale, `USER node`, `HEALTHCHECK`, aucun secret dans `ENV`, `.dockerignore`.

![Trivy avant / après](captures/trivy-before-after.png)

## Partie 5 — GitHub

- *Settings → Code security* : Dependency graph, Dependabot alerts, Dependabot security updates, Secret scanning, Push protection activés.
- [`.github/dependabot.yml`](.github/dependabot.yml) : écosystèmes `npm` et `github-actions`, hebdomadaire.
- CodeQL : *Code scanning → Set up → Default*.

| Faille | Semgrep | CodeQL |
|---|---|---|
| Injection SQL | ✅ `tainted-sql-string` | _à vérifier_ (`js/sql-injection`) |
| Injection de commande | ✅ `detect-child-process` | _à vérifier_ (`js/command-line-injection`) |
| XSS | ✅ `raw-html-format`, `direct-response-write` | _à vérifier_ (`js/reflected-xss`) |

### Workflow [`security.yml`](.github/workflows/security.yml)

| Job | Contrôle | Quality gate |
|---|---|---|
| `secrets` | Gitleaks sur tout l'historique (`fetch-depth: 0`) | échec si secret |
| `sast` | Semgrep `p/javascript` + `p/owasp-top-ten` + règle maison, SARIF publié dans *Security* | échec si résultat |
| `dependencies` | `npm ci --ignore-scripts` + `npm audit --audit-level=high` | échec si HIGH/CRITICAL |
| `image` | build + Trivy image (CRITICAL, `--ignore-unfixed`) + Trivy config | échec si CRITICAL / config HIGH |

- `permissions: contents: read` au niveau du workflow ; `security-events: write` **uniquement** sur `sast` (publication SARIF).
- Actions épinglées par SHA complet : `actions/checkout@3d3c42e… # v7.0.1`, `actions/setup-node@949feb2… # v7.1.0`, `github/codeql-action/upload-sarif@33d7b85… # v4.39.3`.
- **Pourquoi un SHA ?** Un tag (`v7`) peut être déplacé vers un code malveillant si le dépôt de l'Action est compromis ; un SHA de commit est immuable. Dependabot (`github-actions`) propose ensuite les mises à jour du SHA.

### Ruleset sur `main`

Pull Request obligatoire, 1 approbation, checks `secrets`, `sast`, `dependencies` et `image` obligatoires, push direct et force-push interdits.

Une PR qui réintroduit l'injection SQL (`demo/sql-injection`) est bloquée : le check `sast` échoue.

![Dependabot](captures/dependabot-pr.png)
![CodeQL](captures/codeql-alerts.png)
![PR bloquée](captures/pr-blocked.png)

## Partie 6 — Quality gates dans Jenkins

[`Jenkinsfile`](Jenkinsfile) (base TP9) :

```
Checkout → Install → Security ( Gitleaks ∥ Semgrep ∥ npm audit ) → Build → Image scan (Trivy) → post
```

- Stage `Image scan` : `trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed` + `trivy config`.
- Rapports archivés : `archiveArtifacts 'reports/**'` (gitleaks, semgrep, npm-audit, trivy-image, trivy-config).
- Démonstration : branche `demo/sql-injection` → pipeline **rouge** (Semgrep), `main` → pipeline **vert**.

![Jenkins rouge puis vert](captures/jenkins-security.png)

## Défi

### Règle Semgrep personnalisée

[`.semgrep/no-log-req-body.yml`](.semgrep/no-log-req-body.yml) interdit `console.log(req.body)` (et `console.info/warn/error`, `req.body.champ`, `JSON.stringify(req.body)`) : fuite de données personnelles dans les logs (CWE-532, OWASP A09). Elle est chargée par `--config .semgrep` dans GitHub Actions et dans Jenkins.

### `.trivyignore`

[`.trivyignore`](.trivyignore) : une CVE **sans correctif disponible**, avec une justification et une date d'expiration (`exp:AAAA-MM-JJ`).

**Ignorer ≠ accepter un risque.** Ignorer, c'est masquer une alerte (le problème reste invisible et oublié). Accepter un risque, c'est une décision **documentée** : analyse de l'impact, justification, responsable, mesures compensatoires et **date de revue**. Après l'expiration, Trivy signale de nouveau la CVE et la décision doit être reprise.

## Livrables

| Fichier | Contenu |
|---|---|
| `captures/gitleaks.png` | Secrets détectés par Gitleaks |
| `captures/pre-commit-blocked.png` | Commit refusé par le hook |
| `captures/semgrep-before-after.png` | Semgrep avant / après |
| `captures/trivy-before-after.png` | Trivy avant / après |
| `captures/dependabot-pr.png` | PR ouverte par Dependabot |
| `captures/codeql-alerts.png` | Alertes CodeQL |
| `captures/pr-blocked.png` | PR bloquée par un check obligatoire |
| `captures/jenkins-security.png` | Pipeline Jenkins rouge puis vert |
