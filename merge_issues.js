
function mergeIssues (projectId, titleRegex, minCVSS, maxCVSS, hostsRegex, newTitle, newCVSS, update) {
  // Merges all issues identified by the regular expressions into a new or existing Issue
  // provided by newTitle.
  //
  // Usage:
  // mongo localhost:27017/lair --eval "load('./merge_issues.js'); mergeIssues('cvxgsaKNC5cfLoeNn', /Apache/i, 7, 10, /.*/, 'Apache 2.x servers are vulnerable to multiple high risk issues', 'max', false)"
  // mongo localhost:27017/lair --eval "load('./merge_issues.js'); mergeIssues('cvxgsaKNC5cfLoeNn', /Apache/i, 7, 10, /.*/, 'Apache 2.x servers are vulnerable to multiple high risk issues', 'max', true)"
  //
  // projectId - Lair projectId value
  // titleRegex - regex to search titles
  // minCVSS - minimum CVSS score to include
  // maxCVSS - maximum CVSS score to include
  // hostsRegex - host IPs to include in filter
  // newTitle - title of the new Issue
  // newCVSS - new CVSS score, or choose 'max' to pick the highest CVSS score of that group
  // update - The update parameter determines whether it's a 'dry run' with output, or an actual merge. update = true will delete old entries
  //
  // Created by: Matt Burch
  //
  // Original Browser Script
  // Created by: Alex Lauerman and Tom Steele

  // Do some light variable checking, you're still pretty much on your own
  if (typeof titleRegex !== 'object') {
    return print('Issue regex can not be a string, must be a object')
  }
  if (typeof newTitle !== 'string') {
    return print('Invalid title')
  }
  if (typeof newCVSS !== 'string') {
    return print('Invalid cvss. Variable must be a string')
  }
  if (typeof projectId !== 'string') {
    return print('Invalid projectId')
  }

  var modifyBy = 'mongo-mergeIssues'
  var issues = db.issues.find({
    'projectId': projectId,
    'title': {
      '$regex': titleRegex
    },
    'cvss': {
      '$gte': minCVSS,
      '$lte': maxCVSS
    },
    'hosts.ipv4': {
      '$regex': hostsRegex
    }
  }).toArray()
  if (issues.length < 1) {
     return print('Did not find any issues with the given regex')
  }

  var highestCVSS = 0

  IssueRating = function (cvss) {
    var rating = ''
    if (cvss >= 7.0) {
        return rating = 'high'
    } else if ( cvss >= 4.0 && cvss < 7.0) {
        return rating = 'medium'
    } else if (cvss < 4.0) {
        return rating = 'low'
    }
     return rating
  }


  // You can change the sort order here
  // issues.sort(sortByHostCount)
  issues.sort(sortByTitle)
  // issues.sort(sortByCVSS)
  issues.forEach(function (Issue) {
    print('CVSS: ' + Issue.cvss + ' - Hosts: ' + Issue.hosts.length + ' - Title: ' + Issue.title)
    if (Issue.cvss > highestCVSS) {
      highestCVSS = Issue.cvss
    }
  })

  print('Total found: ' + issues.length + ' Highest CVSS: ' + highestCVSS)

  if (update) {
    if (newCVSS === 'max') {
      newCVSS = highestCVSS
    }

    var newDescription = ''
    var newSolution = ''
    var newEvidence = ''
    var newNotes = []
    var newReferences = []
    var cves = []
    var hostList = []
    var newFiles = []
    // If the Issue given in newTitle already exists, then we push it onto the regex list so we can combine them
    // Remove the existing Issue first
    var existingIssue = db.issues.findOne({
      'projectId': projectId,
      'title': newTitle
    })
    if (existingIssue !== null) {
      issues.push(existingIssue)
      db.issues.remove({
        projectId: projectId,
        _id: existingIssue._id
      })
      newDescription = existingIssue.description
    }
    print('Going to merge ' + issues.length + ' issues')

    // Loop over each Issue and combine the data
    issues.forEach(function (Issue) {
      newDescription = newDescription + 'CVSS: ' + Issue.cvss + ' - Hosts: ' + Issue.hosts.length + ' - Title: ' + Issue.title + "\n"
      newSolution = ''
      newEvidence = ''
      newReferences = newReferences.concat(Issue.references)
      newNotes = newNotes.concat(Issue.notes)
      cves = cves.concat(Issue.cves)
      hostList = hostList.concat(Issue.hosts)
      newFiles = newFiles.concat(Issue.files)
    })
    var newHostList = unique(hostList)
    var newCVEs = unique(cves)

    // Create the new Issue
    var id = ObjectId().valueOf()
    if (db.issues.findOne({
      projectId: projectId,
      title: newTitle
    })) {
      return print('An Issue with that title alrady exists')
    }
    db.issues.insert({
      _id: id,
      projectId: projectId,
      title: newTitle,
      cvss: newCVSS,
      rating: IssueRating(newCVSS),
      isConfirmed: false,
      description: newDescription,
      evidence: newEvidence,
      solution: newSolution,
      hosts: [],
      pluginIds: [{
        tool: "Manual",
        id: ObjectId().valueOf()
      }],
      cves: [],
      references: [],
      identifiedBy: [{ tool: "Manual"}],
      notes: [],
      lastModifiedBy: "mongo-mergeIssues",
      isFlagged: false,
      status: "lair-grey",
      files: []
    })
    var newissue = db.issues.findOne({
      _id: id,
      projectId: projectId,
    })
    addExistingContentToIssue(newissue._id)
    print('Complete')
  }

  function sortByHostCount (a, b) {
    if (a.hosts.length > b.hosts.length) {
      return -1
    }
    if (a.hosts.length < b.hosts.length) {
      return 1
    }
    return 0
  }

  function sortByTitle (a, b) {
    if (a.hosts.title > b.hosts.title) {
      return -1
    }
    if (a.hosts.title < b.hosts.title) {
      return 1
    }
    return 0
  }

  function sortByCVSS (a, b) {
    if (a.cvss > b.cvss) {
      return -1
    }
    if (a.cvss < b.cvss) {
      return 1
    }
    return 0
  }

  // Adds notes, hosts, and cves to new vulnerablity
  function addExistingContentToIssue (issueId) {
    newNotes.forEach(function (note) {
      var tmpnote = {
        title: note.title,
        content: note.content,
        lastModifiedBy: modifyBy
      }
      db.issues.update({
        projectId: projectId,
        _id: issueId
      }, {
        $push: {
          notes: tmpnote
        },
        $set: {
          lastModifiedBy: modifyBy
        }
      })
    })
    newHostList.forEach(function (host) {
      var tmphost = db.hosts.findOne({
        projectId: projectId,
        ipv4: host.ipv4
      })
      if (!tmphost) {
        return print('Host not found')
      }
      if (!db.services.findOne({
        projectId: projectId,
        hostId: tmphost._id,
        port: host.port,
        protocol: host.protocol
      })) {
        return print('Service not found')
      }
      db.issues.update({
        projectId: projectId,
        _id: issueId
      }, {
        $addToSet: {
          hosts: {
            ipv4: host.ipv4,
            port: host.port,
            protocol: host.protocol
          }
        },
        $set: {
          lastModifiedBy: modifyBy
        }
      })

    })
    newCVEs.forEach(function (cve) {
      db.issues.update({
        projectId: projectId,
        _id: issueId
      }, {
        $addToSet: {
          cves: cve
        },
        $set: {
          lastModifiedBy: modifyBy
        }
      })
    })
    newReferences.forEach(function (ref) {
      db.issues.update({
        projectId: projectId,
        _id: issueId
      }, {
        $addToSet: {
          references: ref
        },
        $set: {
          lastModifiedBy: modifyBy
        }
      })
    })
    // newFiles.forEach(function (file) {
    //
    // })

    // Remove old Issue
    removeIssues()
  }

  // Loop over all issues and remove them
  function removeIssues () {
    print('Removing Issues')
    issues.forEach(function (Issue) {
      db.issues.remove({
        projectId: projectId,
        _id: Issue._id
      })
    })
  }

  function unique (arr) {
    var hash = {}
    var result = []
    for (var i = 0, l = arr.length; i < l; ++i) {
      var objString = JSON.stringify(arr[i])
      if (!hash.hasOwnProperty(objString)) {
        hash[objString] = true
        result.push(arr[i])
      }
    }
     return result
  }
}
