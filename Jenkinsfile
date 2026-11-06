// TP10 partie 6 – Jenkinsfile du TP9 + quality gates de sécurité
// Checkout → Install → Security (Gitleaks ∥ Semgrep ∥ npm audit) → Build → Image scan (Trivy)

pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '10'))
    timeout(time: 30, unit: 'MINUTES')
  }

  environment {
    IMAGE_NAME       = 'vuln-app'
    npm_config_cache = '.npm-cache'
    GITLEAKS_IMAGE   = 'ghcr.io/gitleaks/gitleaks:v8.30.1'
    SEMGREP_IMAGE    = 'semgrep/semgrep:1.184.0'
    TRIVY_IMAGE      = 'aquasec/trivy:0.76.2'
  }

  stages {

    stage('Checkout') {
      steps {
        script { env.SHORT_SHA = env.GIT_COMMIT.take(7) }
        sh 'git log -1 --oneline && mkdir -p reports'
      }
    }

    stage('Install') {
      agent { docker { image 'node:24-alpine'; reuseNode true } }
      steps {
        // --ignore-scripts : aucun script d'installation exécuté (sqlite3 est compilé dans l'image Docker)
        sh 'npm ci --ignore-scripts'
      }
    }

    stage('Security') {
      parallel {

        stage('Gitleaks') {
          steps {
            // même UID que Jenkins : pas de fichiers root dans le workspace, pas d'erreur "dubious ownership"
            sh '''
              set +e  # Jenkins lance sh avec -e : on garde le code retour pour afficher le rapport
              docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" "$GITLEAKS_IMAGE" \
                git /repo --redact --verbose --exit-code 1 > reports/gitleaks.txt 2>&1
              rc=$?; cat reports/gitleaks.txt; exit $rc
            '''
          }
        }

        stage('Semgrep') {
          steps {
            sh '''
              set +e
              docker run --rm -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
                semgrep scan --config p/javascript --config p/owasp-top-ten --config .semgrep \
                --metrics=off --error --exclude reports --exclude node_modules . > reports/semgrep.txt 2>&1
              rc=$?; cat reports/semgrep.txt; exit $rc
            '''
          }
        }

        stage('npm audit') {
          agent { docker { image 'node:24-alpine'; reuseNode true } }
          steps {
            sh '''
              set +e
              npm audit --audit-level=high > reports/npm-audit.txt 2>&1
              rc=$?; cat reports/npm-audit.txt; exit $rc
            '''
          }
        }
      }
    }

    stage('Build') {
      steps {
        sh "docker build --label org.opencontainers.image.revision=${env.GIT_COMMIT} -t ${env.IMAGE_NAME}:${env.SHORT_SHA} ."
      }
    }

    stage('Image scan') {
      steps {
        // Quality gate : le pipeline échoue s'il reste une CVE CRITICAL corrigeable dans l'image
        sh '''
          set +e
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
            -v "$PWD/.trivyignore:/.trivyignore:ro" "$TRIVY_IMAGE" \
            image --exit-code 1 --severity CRITICAL --ignore-unfixed --ignorefile /.trivyignore \
            "$IMAGE_NAME:$SHORT_SHA" > reports/trivy-image.txt 2>&1
          rc=$?; cat reports/trivy-image.txt
          docker run --rm -v "$PWD:/src" "$TRIVY_IMAGE" \
            config --exit-code 1 --severity HIGH,CRITICAL /src > reports/trivy-config.txt 2>&1
          rc2=$?; cat reports/trivy-config.txt
          [ $rc -eq 0 ] && [ $rc2 -eq 0 ]
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
      sh 'docker image rm "$IMAGE_NAME:$SHORT_SHA" || true'
    }
    success { echo '✅ Quality gates OK : aucun secret, aucun résultat SAST bloquant, aucune CVE bloquante' }
    failure { echo '❌ Quality gate en échec : voir les rapports archivés (reports/)' }
    cleanup { cleanWs() }
  }
}
