// TP10 – Configuration lue dans les variables d'environnement.
// Aucun secret dans le code : les valeurs réelles sont dans .env (non versionné)
// ou injectées par la plateforme (Jenkins credentials, secrets GitHub, Kubernetes…).

function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`Variable d'environnement manquante : ${name} (voir .env.example)`);
    process.exit(1);
  }
  return value;
}

module.exports = {
  port: Number(process.env.PORT) || 3000,
  jwt_secret: required("JWT_SECRET"),
  payment_api_key: process.env.PAYMENT_API_KEY || "",
  db_password: process.env.DB_PASSWORD || "",
};
