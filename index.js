const fs = require('fs');
const csv = require('csvtojson')
var services = [];
const node_openssl = require('node-openssl-cert');
const { spawn } = require( 'child_process' );
const moment = require('moment');

/*const options = {
    binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
}*/

//const openssl = new node_openssl(options);
const openssl = new node_openssl();

var normalizeCommand = function(command) {
    let cmd = command.split(' ');
    let outcmd = [];
    let cmdbuffer = [];
    for(let i = 0; i <= cmd.length - 1; i++) {
        if(cmd[i].charAt(cmd[i].length - 1) == '\\') {
            cmdbuffer.push(cmd[i]);
        } else {
            if(cmdbuffer.length > 0) {
                outcmd.push(cmdbuffer.join(' ') + ' ' + cmd[i]);
                cmdbuffer.length = 0;
            } else {
                outcmd.push(cmd[i]);
            }
        }
    }
    return outcmd;
}

var runOpenSSLCommand = function(cmd, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var terminate = false;
    
    if(cmd.indexOf('s_client') >= 0) {
        terminate = true;
    }
    
    const openssl = spawn( 'openssl', normalizeCommand(cmd) );
    
    openssl.stdout.on('data', function(data) {
        stdoutbuff.push(data.toString());
        /*//openssl.stdin.setEncoding('utf-8');
        setTimeout(function() {
            //openssl.stdin.write("QUIT\r");
            //console.log('QUIT\r\n');
            //openssl.stdin.end();
            openssl.kill();
        }, 1000);*/
        if(terminate) {
            //if(data.toString().indexOf('Verify return code: 0 (ok)') >= 0 ) {
            if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
                openssl.kill();
            }
        }
    });

    /*openssl.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    openssl.stderr.on('data', function(data) {
        stderrbuff.push(data.toString());
    });
    
    openssl.on('exit', function(code) {
        if(terminate && code==null) {
            code = 0;
        }
        var out = {
            command: 'openssl ' + cmd,
            stdout: stdoutbuff.join(''),
            stderr: stderrbuff.join(''),
            exitcode: code
        }
        if (code != 0) {
            if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
                //console.log('true');
                callback(false, out);
            } else {
                callback(stderrbuff.join(), out);
            }
        } else {
            callback(false, out);
        }
    });
}

getCertFromNetwork = function(options, callback) {
    const begin = '-----BEGIN CERTIFICATE-----';
    const end = '-----END CERTIFICATE-----';
    options.port = typeof options.port !== 'undefined' ? options.port : 443;
    options.starttls = typeof options.starttls !== 'undefined' ? options.starttls : false;
    options.protocol = typeof options.protocol !== 'undefined' ? options.protocol : 'https';
    
    command = ['s_client -showcerts -connect ' + options.hostname + ':' + options.port];
    
    if(options.sni) {
        command.push('-servername ' + options.sni);
    }
    
    if(options.starttls){
        command.push('-starttls ' + options.protocol);
    }

    if(options.version){
        command.push('-' + options.version);
    }

    //console.log(command);
    runOpenSSLCommand(command.join(' '), function(err, out) {
        if(err) {
            callback(err, false, 'openssl ' + command);
        } else {
            var placeholder = out.stdout.indexOf(begin);
            var certs = [];
            var endoutput = false;
            if(placeholder <= 0) {
                endoutput = true;
                callback('No certificate found in openssl command response', 'No certificate found in openssl command response', 'openssl ' + command);
                return;
            }
            var shrinkout = out.stdout.substring(placeholder);
            //console.log(shrinkout);
            while(!endoutput) {
                let endofcert = shrinkout.indexOf(end);
                certs.push(shrinkout.substring(0, endofcert) + end);
                shrinkout = shrinkout.substring(endofcert); 
                
                placeholder = shrinkout.indexOf(begin);
                //console.log(placeholder);
                if(placeholder <= 0) {
                    endoutput = true;
                } else {
                    shrinkout = shrinkout.substring(placeholder);
                }
            }
            callback(false, certs, 'openssl ' + command);
            return;
        }
    });
}

csv()
.fromFile(process.argv[2])
/*.on('done',(error)=>{
    //after done processing csv, start looping
    servicesLoop(0, function(err, result) {
        if(err) {
            console.log(err);
        } else {
            console.log(result);
        }
    });
})*/
.then((jsonObj)=>{
    services = jsonObj;
    servicesLoop(0, function(err, result) {
        if(err) {
            console.log(err + '\r\n');
        } else {
            //console.log(result);
        }
    });
})

function processService(serviceobj, callback) {
    let starttlsprotocols = ['smtp', 'pop3', 'imap', 'ftp', 'xmpp', 'xmpp-server', 'irc', 'postgres', 'mysql', 'lmtp', 'nntp', 'sieve', 'ldap'];
    let starttls = false;
    let sni = false;
    let protocol = 'https';
    let version = false;

    if(serviceobj.SNI.toUpperCase()=='FALSE') {
        sni = false;
    } else if(serviceobj.SNI.toUpperCase()=='TRUE') {
        sni = serviceobj.Hostname;
    } else {
        sni = serviceobj.SNI;
    }

    if(serviceobj.Protocol.toUpperCase()!='TLS') {
        if(starttlsprotocols.indexOf(serviceobj.Protocol) < 0) {
            callback('Invalid protocol specified for ' + serviceobj.Hostname, false);
            return;
        } else {
            protocol = serviceobj.Protocol;
        }
    }
    if(serviceobj.STARTTLS.toUpperCase()=='TRUE') {
        starttls = true;
    }

    if(serviceobj.Version!='') {
        version = serviceobj.Version
    }

    var netcertoptions = {
        hostname: serviceobj.Hostname,
        port: parseInt(serviceobj.Port),
        starttls: starttls,
        protocol: protocol,
        sni: sni,
	version: version
    }
    getCertFromNetwork(netcertoptions, function(err, response, cmd) {
        //console.log(cmd);
        if(err) {
            callback(err, false);
        } else {
            openssl.getCertInfo(response[0], function(err, props) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(false, {certs: response, cert: props});
                }
            });
        }
    });
}

function evalCert(servicedata, callback) {
    let startdate = moment(servicedata.cert.attributes['Not Before']);
    let enddate = moment(servicedata.cert.attributes['Not After']);
    let now = moment();
    if(now.diff(startdate, 'seconds') >= 0) {
        let expiredays = parseInt(process.argv[3]);
        now.add(expiredays, 'days');
        //console.log(now.diff(enddate, 'seconds'));
        let thirtydaydiff = now.diff(enddate, 'seconds');
        if(thirtydaydiff < 0) {
            callback(0);
        } else {
            if(thirtydaydiff < 60 * 60 * 24 * expiredays) {
                callback(1);
            } else {
                callback(2);
            }
        }
    } else {
        callback(3);
    }
}

function servicesLoop(index, callback) {
    if(index==undefined) {
        index = 0;
    }
    if(index <= services.length - 1) {
        //console.log(index);
        //console.log(services[index]);
        if(services[index].Hostname[0]=='#') {
            servicesLoop(index + 1, callback);
            return;	
        }
        processService(services[index], function(err, resp) {
            if(err) {
                console.log(err);
                console.error('Failed to download certificate on ' + services[index].Hostname + ' port ' + services[index].Port + '\r\n');
            } else {
                evalCert(resp, function(err) {
		    let cn;
                    if(typeof resp.cert.subject.commonName=='object') {
                          cn = resp.cert.subject.commonName[0];
                    } else {
                          cn = resp.cert.subject.commonName;
                    }
                    //console.log(resp.cert.attributes.Thumbprint);
                    if(err==0) {
                        console.log('Certificate on ' + services[index].Hostname + ' port ' + services[index].Port +' is good (' + cn + ' - ' + resp.cert.attributes.Thumbprint + ' - ' + resp.cert.attributes['Not After'] + ')\r\n');
                        //console.log(JSON.stringify(resp.cert, null, 4));
                    } else if(err==1) {
                        console.error('Certificate on ' + services[index].Hostname + ' port ' + services[index].Port +' is expiring soon (' + cn + ' - ' + resp.cert.attributes.Thumbprint  + ' - ' + resp.cert.attributes['Not After'] + ')\r\n');
                        //console.error(JSON.stringify(resp.cert, null, 4));
                    } else if(err==2) {
                        console.error('Certificate on ' + services[index].Hostname + ' port ' + services[index].Port +' is expired (' + cn + ' - ' + resp.cert.attributes.Thumbprint  + ' - ' + resp.cert.attributes['Not After'] + ')\r\n');
                    } else if(err==3) {
                        console.error('Certificate on ' + services[index].Hostname + ' port ' + services[index].Port +' is not valid yet (' + cn + ' - ' + resp.cert.attributes.Thumbprint  + ' - ' + resp.cert.attributes['Not Before'] + ')\r\n');
                    } else {
                        console.error(err + '\r\n');
                    }
                });
                //console.log(resp);
            }
            servicesLoop(index + 1, callback);
        })
    } else {
        callback(false, true);
    }
}
