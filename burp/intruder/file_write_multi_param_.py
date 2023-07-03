################### This section will mostly remain as it is ###################

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )
################### ---------------------------------------- ###################

    # This attack will be similar to ClusterBomb technique
    # As they are nested loops
    # You can do almost anything here, with the power of python, 
    # this will be applied to request params where you have set %s %s in the Request section in the top
    for firstParam in open('/usr/share/dict/words'):
        for secondParam in open('/usr/share/dict/web2'):
            engine.queue(target.req, 
                        [
                            firstParam.rstrip(),
                            secondParam.rstrip()
                        ])


# Do anything with response, let write it to a file.
def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    # add response to the table
    table.add(req)
    data = req.response.encode('utf8')
    # Extract header and body
    header, _, body = data.partition('\r\n\r\n')
    # Save body to file /tmp/turbo.dat
    output_file = open("/tmp/turbo.dat","a+")
    output_file.write(body + "\n")
    output_file.close()

##
##
