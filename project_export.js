function projectExport (projectId) {
  // Exports JSON project data provided by ProjectID
  //
  // Usage:
  // mongo localhost:27017/lair --eval "load('./project_export.js'); projectExport('cvxgsaKNC5cfLoeNn')"
  //
  // Created By: Matt Burch

  if (typeof projectId !== 'string') {
    return print('Invalid projectId')
  }

  var project = db.projects.findOne({_id: projectId})
  if (typeof project === 'undefined') {
    return print('No project matching ID:' + projectId)
  }
  var hosts = db.hosts.find({projectId: projectId}).toArray() || []
  var issues = db.issues.find({projectId: projectId}).toArray() || []
  hosts.forEach(function (host) {
    host.longIpv4Addr = host.longIpv4Addr.toNumber()
    host.services = db.services.find({hostId: host._id}).toArray()
    host.webDirectories = db.web_directories.find({hostId: host._id}).toArray()
  })
  var people = db.people.find({projectId: projectId}).toArray()
  project.hosts = hosts
  project.people = people
  project.issues = issues
  project.credentials = db.credentials.find({projectId: projectId}).toArray()
  project.authInterfaces = db.auth_interfaces.find({projectId: projectId}).toArray()
  project.netblocks = db.netblocks.find({projectid: projectId}).toArray()
  printjson(project)
}
