// Clean/true-negative counterparts to vuln_sinks.groovy for
// jenkins_pipeline_guard.py (v1.23.0) — see that file for the real
// CyberSci motivating case.

pipeline {
  agent any
  stages {
    stage('No parameters block at all') {
      steps {
        // No `parameters { string(...) }` anywhere in this file at all —
        // signal 1 (a declared build parameter) is completely absent, so
        // this must not fire no matter what the sh body references.
        sh '''
          echo "Deploying ${BUILD_NUMBER}"
          docker system prune -f
        '''  // safe: Command Injection
      }
    }
  }
}
