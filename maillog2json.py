#!/usr/bin/env python

import sys, re, time, json, fileinput


def makeISOTime(syslog_time):
    '''
    (Str) -> Str
    '''
    tz = "".join( (time.strftime("%z")[:3], ":", time.strftime("%z")[3:]) )

    syslog_time = " ".join( (time.strftime("%Y"), syslog_time) )
    syslog_time = " ".join(syslog_time.split())
    syslog_time = time.strftime("%Y-%m-%dT%H:%M:%S", time.strptime(syslog_time, "%Y %b %d %H:%M:%S"))
    syslog_time = "".join( (syslog_time, tz) )

    return syslog_time


def printJSON(mails):
    '''
    Prints Dict as JSON document
    (Dict) -> None
    '''
    for mail in mails:
        print(json.dumps(mails[mail]))


def loadLogs():
    '''
    Load lines with QueueID only from all input files
    (None) -> List
    '''
    qids = {}
    logfields = ('datetime', 'host', 'app', 'qid', 'msg')
    logqidmask = re.compile('(\w+\s+\d+\s+\d+\:\d+\:\d+)\s(\S+)\s(\S+)\:\s([\w\d]{11}):\s(.+)')
    appmask = re.compile('postfix/(\w+)\[')

    clientmask = re.compile('client=(.+)\[(.+)\]$')
    pickupmask = re.compile('uid=(\d+) from=<(.*)>$')
    midmask = re.compile('message-id=\<(.+@(.+)|.+)\>')
    frommask = re.compile('from=\<(.*)\>, size=(\d+), nrcpt=(\d+)')
    removedmask = re.compile('removed$')
    tomask = re.compile('^to=<([^,]*?)>, relay=(.+)\[(.+?)\]:(\d+), .*delay=(.+?),.+dsn=(.+), status=(\w+) \((.+)\)$')
    toorigmask = re.compile('to=<(.*?)>, orig_to=<(.*?)>, relay=(.+)\[(.+?)\]:(\d+), delay=(.+?),.+dsn=(.+), status=(\w+) \((.+)\)$')
    addrhostmask = re.compile('.+@(.+)')

    for log in fileinput.FileInput():
        try:
            logentry = { k: v for k, v in zip(logfields, logqidmask.search(log).groups()) }
        except AttributeError as err:
            sys.stderr.write(">>> Ignoring: {}".format(log))
            continue

        logentry['datetime'] = makeISOTime(logentry['datetime'])

        if appmask.search(logentry['app']): 
            logentry['app'] = appmask.search(logentry['app']).group(1)

        if logentry['qid'] not in qids: 
            qids[logentry['qid']] = {
                'mid': "unknown",
                'qid': logentry['qid'],
                'host': logentry['host'],
                'type': "maillog",
                'received': "unknown",
                'client': {},
                'from': "unknown",
                'size': -1,
                'nrcpt': -1,
                'removed': "unknown",
                '@timestamp': "unknown",
                'rcpt': []
            }

        if re.match("(pickup|smtpd)", logentry['app']):
            qids[logentry['qid']]['received'] = logentry['datetime']
            qids[logentry['qid']]['@timestamp'] = logentry['datetime']

            if clientmask.search(logentry['msg']):
                qids[logentry['qid']]['client']['host'] = clientmask.search(logentry['msg']).group(1)
                qids[logentry['qid']]['client']['ip'] = clientmask.search(logentry['msg']).group(2)
            elif pickupmask.search(logentry['msg']):
                qids[logentry['qid']]['client']['login'] = pickupmask.search(logentry['msg']).group(2)
                qids[logentry['qid']]['client']['uid'] = pickupmask.search(logentry['msg']).group(1)
            else:
                sys.stderr.write(">>> Unknown the (pickup|smtpd) string: {}\n".format(log))

        elif re.match("cleanup", logentry['app']):
            if midmask.search(logentry['msg']):
                qids[logentry['qid']]['mid'] = midmask.search(logentry['msg']).group(1)
		if midmask.search(logentry['msg']).group(2):
	            qids[logentry['qid']]['mid_host'] = midmask.search(logentry['msg']).group(2)
		else:
		    qids[logentry['qid']]['mid_host'] = "unknown"
            else:
                sys.stderr.write(">>> Unknown the (cleanup) string: {}\n".format(log))

        elif re.match("qmgr", logentry['app']):
            if frommask.search(logentry['msg']):
                qids[logentry['qid']]['from'] = frommask.search(logentry['msg']).group(1)
		if addrhostmask.search(qids[logentry['qid']]['from']):
		    qids[logentry['qid']]['from_host'] = addrhostmask.search(qids[logentry['qid']]['from']).group(1)
		else:
		    qids[logentry['qid']]['from_host'] = "unknown"
                qids[logentry['qid']]['size'] = int(frommask.search(logentry['msg']).group(2))
                qids[logentry['qid']]['nrcpt'] = int(frommask.search(logentry['msg']).group(3))
            elif removedmask.search(logentry['msg']):
                qids[logentry['qid']]['removed'] = logentry['datetime']
            else:
                sys.stderr.write(">>> Unknown the (qmgr) string: {}\n".format(log))

        elif re.match("(smtp|local|virtual)", logentry['app']):
            rcpt = {}

            if tomask.search(logentry['msg']):
                rcpt['to'] = tomask.search(logentry['msg']).group(1)
		if addrhostmask.search(rcpt['to']):
		    rcpt['to_host'] = addrhostmask.search(rcpt['to']).group(1)
		else:
		    rcpt['to_host'] = "unknown"	
                rcpt['relay'] = {
                    'host': tomask.search(logentry['msg']).group(2),
                    'ip': tomask.search(logentry['msg']).group(3),
                    'port': tomask.search(logentry['msg']).group(4)
                }
                rcpt['delay'] = float(tomask.search(logentry['msg']).group(5))
                rcpt['status'] = {
                    'code': tomask.search(logentry['msg']).group(6),
                    'res': tomask.search(logentry['msg']).group(7),
                    'msg': tomask.search(logentry['msg']).group(8)
                }
                rcpt['sent'] = logentry['datetime']
            elif toorigmask.search(logentry['msg']):
                rcpt['to'] = toorigmask.search(logentry['msg']).group(1)
		if addrhostmask.search(rcpt['to']):
		    rcpt['to_host'] = addrhostmask.search(rcpt['to']).group(1)
		else:
		    rcpt['to_host'] = "unknown"	
                rcpt['orig'] = toorigmask.search(logentry['msg']).group(2)
		if addrhostmask.search(rcpt['orig']):
		    rcpt['orig_host'] = addrhostmask.search(rcpt['orig']).group(1)
		else:
		    rcpt['orig_host'] = "unknown"	
                rcpt['relay'] = {
                    'host': toorigmask.search(logentry['msg']).group(3),
                    'ip': toorigmask.search(logentry['msg']).group(4),
                    'port': toorigmask.search(logentry['msg']).group(5)
                }
                rcpt['delay'] = float(toorigmask.search(logentry['msg']).group(6))
                rcpt['status'] = {
                    'code': toorigmask.search(logentry['msg']).group(7),
                    'res': toorigmask.search(logentry['msg']).group(8),
                    'msg': toorigmask.search(logentry['msg']).group(9)
                }
                rcpt['sent'] = logentry['datetime']
            else:
                sys.stderr.write(">>> Unknown the (smtp|local|virtual) string: {}\n".format(log))

            qids[logentry['qid']]['rcpt'].append(rcpt)
            del(rcpt)
        else:
            sys.stderr.write(">>> Unknown the log string: {}\n".format(log))

    return qids


if __name__ == "__main__":
    printJSON(loadLogs())
