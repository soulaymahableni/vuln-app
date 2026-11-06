# TP10 – Dockerfile corrigé : image récente, multi-stage, utilisateur non root, aucun secret.

# --- Étape 1 : installation des dépendances (outils de compilation pour sqlite3 si besoin) ---
FROM node:24-alpine AS deps
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# --- Étape 2 : image finale minimale ---
FROM node:24-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

# npm, npx, corepack et yarn ne servent pas à l'exécution : on les retire
# (moins de paquets = moins de CVE remontées par Trivy)
RUN rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*

COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src

USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- "http://127.0.0.1:3000/hello?name=health" || exit 1
# Les secrets (JWT_SECRET…) sont fournis au lancement : docker run --env-file .env …
CMD ["node", "src/server.js"]
