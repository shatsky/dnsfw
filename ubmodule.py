log_info("DNSFW content filtering Python module for Unbound DNS")
'''
 Copyright (c) 2016, Eugene Shatsky (eugene AT shatsky.net)

 Based on resgen.py and resip.py examples
 https://github.com/jedisct1/unbound/tree/master/pythonmod/examples

 Copyright (c) 2009, Zdenek Vasicek (vasicek AT fit.vutbr.cz)
                     Marek Vavrusa  (xvavru00 AT stud.fit.vutbr.cz)

 This software is open source.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 
    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
 
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
 
    * Neither the name of the organization nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
'''

import os, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import domains

def init(id, cfg): return True

def deinit(id): return True

def inform_super(id, qstate, superqstate, qdata): return True

def operate(id, event, qstate, qdata):
    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        # get client address
        # why is there a chain structure?
        # is it guaranteed that first reply_list.query_reply.addr is addr for current request?
        client_addr = '0.0.0.0'
        reply_list = qstate.mesh_info.reply_list
        while reply_list:
            if reply_list.query_reply:
                client_addr = reply_list.query_reply.addr
                break
            reply_list = reply_list.next
        #log_info('Client '+client_addr+' requests '+qstate.qinfo.qname_str[:-1])
        # check if queried domain is in blocked category for the querying client
        # why does domain have extra '.' in the end and why does the server request 'domain.lan.' on 'domain.' failure?
        if not domains.domain_allowed_for_addr(qstate.qinfo.qname_str[:-1], client_addr):
            #create instance of DNS message (packet) with given parameters
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            #append RR
            if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                # The TTL of 0 is mandatory, otherwise it ends up in
                # the cache, and is returned to other IP addresses.
                # TODO: if allowed/blocked for all clients, set non-zero TTL
                # If a client requests domain which is not blocked for him, won't the reply be cached and returned to others?
                msg.answer.append("%s 0 IN A 127.0.0.1" % qstate.qinfo.qname_str)
            #set qstate.return_msg 
            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR 
                return True

            #we don't need validation, result is valid
            qstate.return_msg.rep.security = 2

            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED 
            return True
        else:
            #pass the query to validator
            qstate.ext_state[id] = MODULE_WAIT_MODULE 
            return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
