function issueCVEReplace (projectId, title, cveList) {
  // Replaces Issue CVEs with provided cveList
  //
  // Usage:
  // mongo localhost:27017/lair --eval "load('./issue_cve_replace.js'); issueCVEReplace('cvxgsaKNC5cfLoeNn', 'Some Issue', ['2015-0123', '2015-0133'])"
  //
  // Created By: Matt Burch

  if (typeof projectId !== 'string') {
    return print('Invalid projectId')
  }
  if (typeof title !== 'string') {
    return print('Invalid Issue title')
  }
  if (typeof cveList !== 'object') {
    return print('Issue cveList can not be a string, must be a object')
  }

  var issue = db.issues.findOne({
    projectId: projectId,
    title: title,
  })

  if (issue == null) {
    return print('Did not find any issues with the given title')
  }

  print('Clearing ' + issue.cves.length + ' CVEs')
  issue.cves = []
  print('Setting ' + cveList.length + ' CVEs')
  issue.cves = cveList
  db.issues.update({
    projectId: projectId,
    title: title,
    }, issue )
}
