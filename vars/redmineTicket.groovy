// =============================================================================
// redmineTicket  —  creates Redmine tickets for gitleaks findings (secrets only)
// -----------------------------------------------------------------------------
// - One ticket per secret found.
// - No duplicates: each subject has a marker like [SEC-1a2b3c4d5e6f]. If an OPEN ticket
//   with that marker already exists, nothing new is created.
// - Secret values are never sent (gitleaks runs with --redact).
// - If Redmine is down or returns an error, the build does NOT fail; it is only logged.
//
// Usage in a Jenkinsfile:
//   def secrets = securityScan.gitleaks()
//   redmineTicket(
//     findings     : secrets,
//     url          : 'https://redmine.yourcompany.com',
//     project      : 'security',          // Redmine project identifier
//     credentialsId: 'redmine-api-key',   // Jenkins "Secret text" credential with the Redmine API key
//     dryRun       : true                 // true = only print, false = really create tickets
//   )
//
// Optional: trackerId, priorityId, assigneeId (numbers from your Redmine), maxTickets (default 20)
// =============================================================================

import groovy.json.JsonOutput

List call(Map cfg) {
  List findings  = cfg.findings ?: []
  String url     = "${cfg.url ?: ''}".replaceAll('/+$', '')
  String project = "${cfg.project ?: ''}"
  String credsId = cfg.credentialsId ?: 'redmine-api-key'
  boolean dryRun = cfg.dryRun == null ? true : cfg.dryRun
  int maxTickets = cfg.maxTickets ?: 20

  if (!findings) { echo 'Redmine: no secrets, no tickets'; return [] }
  if (!url || !project) { error('redmineTicket: "url" and "project" are required') }

  if (findings.size() > maxTickets) {
    echo "Redmine: ${findings.size()} findings, creating only the first ${maxTickets}"
    findings = findings.subList(0, maxTickets)
  }

  String repo = env.GIT_URL ? env.GIT_URL.replaceAll(/\.git$/, '').tokenize('/:').last() : "${env.JOB_NAME}"
  List results = []

  // ---- dry run: show what would be created
  if (dryRun) {
    for (def f : findings) {
      String subject = subjectFor(f, repo)
      echo "Redmine DRY RUN - would create: ${subject}"
      results << [status: 'dry-run', id: null, subject: subject]
    }
    return results
  }

  // ---- create tickets
  withCredentials([string(credentialsId: credsId, variable: 'REDMINE_API_KEY')]) {
    for (def f : findings) {
      String subject = subjectFor(f, repo)
      String marker  = markerFor(f)
      try {
        def existing = findOpenIssue(url, project, marker)
        if (existing) {
          echo "Redmine: already open #${existing} -> ${subject}"
          results << [status: 'exists', id: existing, subject: subject]
          continue
        }
        Map issue = [project_id: project, subject: subject, description: descriptionFor(f, repo)]
        if (cfg.trackerId)  { issue.tracker_id     = cfg.trackerId }
        if (cfg.priorityId) { issue.priority_id    = cfg.priorityId }
        if (cfg.assigneeId) { issue.assigned_to_id = cfg.assigneeId }

        def id = createIssue(url, issue)
        echo "Redmine: created #${id} -> ${subject}"
        results << [status: 'created', id: id, subject: subject]
      } catch (err) {
        echo "Redmine: could not create ticket (${err.getMessage()}) -> ${subject}"
        results << [status: 'error', id: null, subject: subject]
      }
    }
  }
  return results
}

// -----------------------------------------------------------------------------
// Redmine REST API (curl). The API key is read from the environment, never printed.
// -----------------------------------------------------------------------------
def findOpenIssue(String url, String project, String marker) {
  String out = sh(returnStdout: true, script: """
    curl -sS -f -g -G "${url}/issues.json" \\
      -H "X-Redmine-API-Key: \$REDMINE_API_KEY" \\
      --data-urlencode "project_id=${project}" \\
      --data-urlencode "set_filter=1" \\
      --data-urlencode "f[]=status_id" --data-urlencode "op[status_id]=o" \\
      --data-urlencode "f[]=subject"   --data-urlencode "op[subject]=~" \\
      --data-urlencode "v[subject][]=${marker}" \\
      --data-urlencode "limit=1"
  """).trim()
  def resp = readJSON(text: out)
  return (resp.issues && resp.issues.size() > 0) ? resp.issues[0].id : null
}

def createIssue(String url, Map issue) {
  writeFile file: '.security/redmine-issue.json', text: JsonOutput.toJson([issue: issue])
  String out = sh(returnStdout: true, script: """
    curl -sS -f -X POST "${url}/issues.json" \\
      -H "Content-Type: application/json" \\
      -H "X-Redmine-API-Key: \$REDMINE_API_KEY" \\
      --data-binary @.security/redmine-issue.json
  """).trim()
  sh 'rm -f .security/redmine-issue.json'
  return readJSON(text: out).issue.id
}

// -----------------------------------------------------------------------------
// Ticket text
// -----------------------------------------------------------------------------
String subjectFor(Map f, String repo) {
  String s = "[${markerFor(f)}] Secret found: ${f.rule} in ${f.file} (${repo})".toString()
  return s.length() > 250 ? s.substring(0, 247) + '...' : s
}

String markerFor(Map f) {
  return 'SEC-' + shortHash(f.fingerprint)
}

String descriptionFor(Map f, String repo) {
  return """\
*A secret was found in the code by Jenkins (gitleaks).*

| Repository | ${repo} |
| Secret type | ${f.rule} (${f.description}) |
| File | ${f.file} line ${f.line} |
| Commit | ${f.commit} |
| Author | ${f.author} <${f.email}> |
| Date | ${f.date} |
| Build | ${env.BUILD_URL ?: 'n/a'} |
${f.link ? "| Link | ${f.link} |\n" : ''}
*What to do*
# REVOKE / rotate the secret where it was created (AWS IAM, database, provider console).
# Put the new secret in Jenkins Credentials or AWS Secrets Manager.
# Remove the secret from the code. Deleting the commit is NOT enough: the old value must stop working.
# Add proof of revocation to this ticket, then close it.

Do NOT paste the secret value into this ticket.
Fingerprint: ${f.fingerprint}
""".toString()
}

@NonCPS
static String shortHash(String text) {
  def md = java.security.MessageDigest.getInstance('SHA-256')
  return md.digest(text.getBytes('UTF-8')).encodeHex().toString().substring(0, 12)
}