// Jenkins declarative-pipeline parameter injection (jenkins_pipeline_guard.py,
// v1.23.0). Found via the real CyberSci nationals-2025-26 "deployment_hell"
// defence challenge's service/jenkins/scripts/deploy-app.groovy and
// build-and-upload.groovy: a `string(name: 'projectName', ...)` build
// parameter is aliased to an env var (`env.PROJECT_NAME = params.projectName`)
// and from there straight into a `sh` step's own body — Jenkins substitutes
// `${PROJECT_NAME}` as literal shell text before invoking /bin/sh, so anyone
// able to trigger a parameterized build controls part of the command run on
// the agent.

pipeline {
  agent any
  parameters {
    string(
      name: 'projectName',
      defaultValue: 'canary',
      description: 'name of the project to deploy'
    )
    string(
      name: 'unusedParam',
      defaultValue: 'nope',
      description: 'declared but never referenced in any sh step — must NOT fire on its own'
    )
  }
  stages {
    stage('Load env alias') {
      steps {
        script {
          env.PROJECT_NAME = params.projectName
        }
      }
    }
    stage('Build via env-aliased param — multi-line sh') {
      steps {
        sh '''  // ruleid: Command Injection
          docker save ${PROJECT_NAME}:latest -o /tmp/${PROJECT_NAME}.tar
        '''
      }
    }
    stage('Build via direct params.X reference — single-line sh') {
      steps {
        sh "docker build -t ${params.projectName}:latest ."  // ruleid: Command Injection
      }
    }
    stage('Unrelated, non-tainted sh step') {
      steps {
        // No build parameter or alias referenced anywhere in this body —
        // just a fixed, hardcoded command. Must NOT fire.
        sh 'docker system prune -f'  // safe: Command Injection
      }
    }
  }
}
