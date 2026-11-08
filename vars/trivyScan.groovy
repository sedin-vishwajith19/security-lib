// =============================================================================
// trivyScan  —  Docker image scan (vulnerabilities)
// -----------------------------------------------------------------------------
// Policy:
//   - CRITICAL vulnerabilities above the limit   -> build FAILS (image must not be deployed)
//   - CRITICAL vulnerabilities up to the limit   -> build UNSTABLE
//   - only HIGH / MEDIUM / LOW                   -> shown in the log and report only
//
// Usage in a Jenkinsfile:
//   trivyScan(image: 'myapp:1.2.3')                       // default limit: 5 CRITICAL
//   trivyScan(image: 'myapp:1.2.3', maxCritical: 0)       // stricter: any CRITICAL fails
//
// Options:
//   image       (required) image to scan, e.g. 123456789012.dkr.ecr.ap-south-1.amazonaws.com/myapp:1.2.3
//   maxCritical (default 5)    how many CRITICAL vulnerabilities are allowed before the build fails
//   onlyFixable (default true) count only CRITICAL vulnerabilities that already have a fix
//                              (ones without a fix can't be solved by the team yet)
//   report      (default 'trivy-report.json')
// =============================================================================

Map call(Map args) {
  String image = args.image
  if (!image) { error('trivyScan: "image" is required') }
  int maxCritical     = args.maxCritical != null ? (args.maxCritical as int) : 5
  boolean onlyFixable = args.onlyFixable != null ? args.onlyFixable : true
  String report       = args.report ?: 'trivy-report.json'
  String htmlReport   = report.replaceAll(/\.json$/, '') + '.html'

  sh """
    trivy image \\
      --scanners vuln \\
      --format json \\
      --output ${report} \\
      --exit-code 0 \\
      --no-progress \\
      '${image}'

    # Same report as HTML (easy to read / share)
    if [ -f /opt/trivy/contrib/html.tpl ]; then
      trivy convert --format template --template "@/opt/trivy/contrib/html.tpl" \\
        --output ${htmlReport} ${report} || echo "HTML report skipped"
    fi
  """
  archiveArtifacts artifacts: "${report}, ${htmlReport}", allowEmptyArchive: true

  // ---- count
  def data = readJSON(file: report)
  int critical = 0, criticalFixable = 0, high = 0, medium = 0, low = 0
  List criticalList = []
  for (def res : (data.Results ?: [])) {
    for (def v : (res.Vulnerabilities ?: [])) {
      switch ("${v.Severity}".toString()) {
        case 'CRITICAL':
          critical++
          if (v.FixedVersion) { criticalFixable++ }
          criticalList << "${v.VulnerabilityID} ${v.PkgName} ${v.InstalledVersion} -> fix: ${v.FixedVersion ?: 'none yet'}".toString()
          break
        case 'HIGH':   high++;   break
        case 'MEDIUM': medium++; break
        default:       low++
      }
    }
  }
  def os = data.Metadata?.OS
  boolean eol = os?.EOSL ? true : false

  // ---- show
  echo """Trivy: ${image}
  CRITICAL: ${critical} (with fix: ${criticalFixable})
  HIGH    : ${high}
  MEDIUM  : ${medium}
  LOW     : ${low}
  Base OS : ${os ? "${os.Family} ${os.Name}" : 'unknown'}${eol ? '  <-- END OF LIFE, no more security updates' : ''}"""
  int shown = 0
  for (def c : criticalList) {
    if (shown++ >= 30) { echo "  ... ${criticalList.size() - 30} more in ${report}"; break }
    echo "  CRITICAL ${c}"
  }

  // ---- decide
  int counted = onlyFixable ? criticalFixable : critical
  String what = onlyFixable ? 'fixable CRITICAL' : 'CRITICAL'
  if (counted > maxCritical) {
    error("Trivy: ${counted} ${what} vulnerabilities in ${image} (limit is ${maxCritical}). Build stopped: do not deploy this image.")
  } else if (critical > 0) {
    unstable("Trivy: ${critical} CRITICAL vulnerabilities in ${image} (within the limit of ${maxCritical}). Plan an update.")
  } else {
    echo "Trivy: no CRITICAL vulnerabilities"
  }

  return [critical: critical, criticalFixable: criticalFixable, high: high, medium: medium, low: low, eol: eol]
}