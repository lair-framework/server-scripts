function dumpServiceNotes (projectId, noteRegex, iplist) {
  // Dump the contents of service notes matching a specific regex (matches against note 'title')
  // By supplying an empty string for the 'ip' you can dump all notes.
  // Examples:
  //   dumpServiceNotes('^SSL Self-Signed', '')
  //   dumpServiceNotes('Software Enumeration', '192.168.1.1')
  //
  // Usage: mongo localhost:27017/lair --eval "load('./dump_service_notes.js'); dumpServiceNotes('^SSL Self-Signed', '')"
  //
  // Created by: Matt Burch
  //
  // Original Browser Script
  // Created by: Dan Kottmann

  function checkmatch (host, iplist) {
    skp = 1
    if (iplist.length < 1) {
      return 0
    }
    iplist.forEach( function(ip) {
      if (ip !== '' && ip == host.ipv4) {
        skp = 0
        return
      }
    })
    return skp
  }

  var hostIds = []
  var re = new RegExp(noteRegex, 'i')
  var services = db.services.find({
    'projectId': projectId,
    'notes': {
      $elemMatch: {
        'title': {
          $regex: noteRegex,
          $options: 'i'
        }
      }
    }
  }, {
    notes: 1,
    hostId: 1
  }).toArray()
  services.map( function(service) {
    hostIds.push(service.hostId)
  })

  var hosts = db.hosts.find({
    '_id': {
      $in: hostIds
    }
  }).sort({
    longIpv4Addr: 1,
    ipv4: 1
  }).toArray()
  hosts.forEach(function (host) {
    if (checkmatch(host,iplist)) {
      return
    }
    services = db.services.find({
      'hostId': host._id
    }).sort({
        service: 1,
        notes: 1,
        service: 1,
        protocol: 1
    }).toArray()
    services.forEach(function (service) {
      service.notes.forEach(function (note) {
        if (re.test(note.title)) {
          print(host.ipv4 + ':' + service.port + '/' + service.protocol + ' - ' + note.title + '\n' + note.content)
        }
      })
    })
  })
}
