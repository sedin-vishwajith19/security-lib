// =============================================================================
// securityScan  —  gitleaks (secrets) + Semgrep (Dockerfile, Docker Compose, code)
// -----------------------------------------------------------------------------
// Policy:
//   - These scans NEVER fail the build.
//   - If anything is found, the build is marked UNSTABLE (yellow).
//   - gitleaks returns its findings, so the pipeline can create Redmine tickets.
//
// Usage in a Jenkinsfile:
//   def secrets = securityScan.gitleaks()
//   securityScan.semgrep(languages: ['python', 'javascript'])
//
// Rule files come from this library (resources/ folder), not from the app repo.
// =============================================================================

// -----------------------------------------------------------------------------
// gitleaks: secrets in code and in the full Git history
// -----------------------------------------------------------------------------
List gitleaks(Map args = [:]) {
  String report = args.report ?: 'gitleaks-report.json'

  writeFile file: '.security/gitleaks.toml', text: libraryResource('gitleaks/gitleaks.toml')

  sh """
    # If the repo has a baseline, findings already handled are not reported again
    BASELINE=""
    [ -f .gitleaks-baseline.json ] && BASELINE="--baseline-path .gitleaks-baseline.json"

    gitleaks git . \\
      --config .security/gitleaks.toml \$BASELINE \\
      --redact \\
      --report-format json \\
      --report-path ${report} \\
      --exit-code 0
  """
  archiveArtifacts artifacts: report, allowEmptyArchive: true

  def data = readJSON(file: report) ?: []
  List findings = []
  for (def f : data) {
    findings << [
      rule       : "${f.RuleID}".toString(),
      description: "${f.Description}".toString(),
      file       : "${f.File}".toString(),
      line       : f.StartLine,
      commit     : "${f.Commit}".toString(),
      author     : "${f.Author}".toString(),
      email      : "${f.Email}".toString(),
      date       : "${f.Date}".toString(),
      link       : f.Link ? "${f.Link}".toString() : '',
      fingerprint: "${f.Fingerprint}".toString(),
    ]
  }

  if (findings) {
    echo "gitleaks: ${findings.size()} secret(s) found"
    for (def f : findings) {
      echo "  ${f.rule} -> ${f.file}:${f.line} (commit ${f.commit.take(8)}, ${f.author})"
    }
    unstable("gitleaks: ${findings.size()} secret(s) found. See ${report}")
  } else {
    echo 'gitleaks: no secrets found'
  }
  return findings
}

// -----------------------------------------------------------------------------
// Semgrep: Dockerfile + Docker Compose (always) + application code (languages)
//
//   languages: list of programming languages of the project, e.g.
//              ['python'], ['javascript'], ['typescript'], ['java'], ['go'], ['php']
//              Leave empty to scan only Dockerfile + Compose.
// -----------------------------------------------------------------------------
Map semgrep(Map args = [:]) {
  List languages   = args.languages ?: []
  String report    = args.report ?: 'semgrep-report.json'
  String community = args.communityRules ?: '/opt/semgrep-rules/community'

  // our custom Dockerfile + Compose rules (from this library)
  writeFile file: '.security/semgrep/dockerfile-custom.yaml', text: libraryResource('semgrep/dockerfile-custom.yaml')
  writeFile file: '.security/semgrep/compose-custom.yaml',    text: libraryResource('semgrep/compose-custom.yaml')

  // rule folders: Dockerfile community rules + one folder per language
  List ruleDirs = ["${community}/dockerfile".toString()]
  for (def lang : languages) {
    for (def d : languageFolders("${lang}".toString())) {
      String dir = "${community}/${d}".toString()
      if (!ruleDirs.contains(dir)) { ruleDirs << dir }
    }
  }
  String configArgs = ''
  for (def d : ruleDirs) { configArgs += " --config ${d}" }

  echo "Semgrep: languages = ${languages ?: 'none (Dockerfile + Compose only)'}"

  sh """
    # stop with a clear message if a rule folder is missing
    for d in ${ruleDirs.join(' ')}; do
      [ -d "\$d" ] || { echo "Semgrep rules folder not found: \$d"; exit 1; }
    done

    # Semgrep only auto-detects files named Dockerfile or *.dockerfile; pass others explicitly
    EXTRA_DOCKERFILES=\$(find . -path ./.git -prune -o -type f \\( -name 'Dockerfile.*' -o -name '*.Dockerfile' \\) -print | tr '\\n' ' ')

    semgrep scan ${configArgs} \\
      --config .security/semgrep/ \\
      --exclude .security \\
      --scan-unknown-extensions \\
      --metrics=off \\
      --disable-version-check \\
      --json -o ${report} \\
      . \$EXTRA_DOCKERFILES
  """
  archiveArtifacts artifacts: report, allowEmptyArchive: true

  def data = readJSON(file: report)
  List issues = []   // security problems -> shown + UNSTABLE
  int other = 0      // best-practice / info -> counted only
  for (def r : (data.results ?: [])) {
    String ruleId = r.check_id.tokenize('.').last()
    boolean ourRule    = ruleId.startsWith('dockerfile-') || ruleId.startsWith('compose-')
    boolean dockerRule = r.check_id.contains('dockerfile')
    boolean security   = ourRule || dockerRule || (r.extra?.metadata?.category == 'security')
    boolean important  = r.extra.severity in ['ERROR', 'WARNING']

    if (security && important) {
      issues << "${r.extra.severity == 'ERROR' ? 'HIGH  ' : 'MEDIUM'} ${ruleId} -> ${r.path}:${r.start.line}".toString()
    } else {
      other++
    }
  }

  echo "Semgrep: ${issues.size()} security issue(s), ${other} other suggestion(s)"
  int shown = 0
  for (def i : issues) {
    if (shown++ >= 50) { echo "  ... ${issues.size() - 50} more in ${report}"; break }
    echo "  ${i}"
  }
  for (def e : (data.errors ?: [])) { echo "Semgrep warning: ${e.message}" }

  if (issues) {
    unstable("Semgrep: ${issues.size()} security issue(s) found. See ${report}")
  }
  return [issues: issues.size(), other: other]
}

// -----------------------------------------------------------------------------
// Language name -> Semgrep community rule folder(s)
// -----------------------------------------------------------------------------
@NonCPS
static List languageFolders(String lang) {
  Map map = [
    'python'    : ['python'],
    'java'      : ['java'],
    'javascript': ['javascript'], 'js': ['javascript'], 'node': ['javascript'], 'nodejs': ['javascript'],
    'typescript': ['javascript', 'typescript'], 'ts': ['javascript', 'typescript'],
    'go'        : ['go'], 'golang': ['go'],
    'php'       : ['php'],
    'ruby'      : ['ruby'],
    'csharp'    : ['csharp'], 'c#': ['csharp'], 'dotnet': ['csharp'],
    'kotlin'    : ['kotlin'],
    'scala'     : ['scala'],
    'rust'      : ['rust'],
    'swift'     : ['swift'],
    'bash'      : ['bash'], 'shell': ['bash'],
    'terraform' : ['terraform'],
  ]
  List dirs = map[lang.toLowerCase().trim()]
  if (dirs == null) {
    throw new IllegalArgumentException("securityScan.semgrep: unknown language '${lang}'. Use one of: ${map.keySet().join(', ')}")
  }
  return dirs
}
