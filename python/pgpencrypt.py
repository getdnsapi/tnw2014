#
# an example of using getdns to pull out a pgp record,
# extract the public key, and then
# encrypt some text
#
# requires the following Python modules:
#    getdns
#    python-gnupg
#    base64
#


import getdns
import gnupg
import base64
import sys
import string

PGP_TYPE = 65280

# 
# I commented out the "return None" because this is demo code and you
# should be able to play with it.  But, in deployed applications you
# MUST check that dnssec_status is GETDNS_DNSSEC_SECURE
#

def get_first_secure_response(results):
    replies_tree = results['replies_tree']
    if (not replies_tree) or (not len(replies_tree)) or (not replies_tree[0]['answer']) or (not len(replies_tree[0]['answer'])):
        print 'empty answer list'
        return None
    else:
        reply = replies_tree[0]
        if reply['dnssec_status'] != getdns.GETDNS_DNSSEC_SECURE:
            print 'insecure reply'
#            return None                      
        answer = replies_tree[0]['answer']
        record = [ x for x in answer if x['type'] == PGP_TYPE ]
        if len(record) == 0:
            print 'no answers of type PGP_TYPE'
            return None
        return record[0]
    
def main():
    pgp_name = "77fa5113ab6a532ce2e6901f3bd3351c0db5845e0b1b5fb09907808d._openpgpkey.getdnsapi.net"

    if len(sys.argv) == 2:
        pgp_name = sys.argv[1]
    c = getdns.context_create()
    extensions = { 'dnssec_return_status' : getdns.GETDNS_EXTENSION_TRUE }
    results = getdns.general(c, pgp_name, PGP_TYPE, extensions=extensions)
    if results['status'] != getdns.GETDNS_RESPSTATUS_GOOD:
        print 'query status is {0}'.format(results['status'])
        sys.exit(1)
    else:
        gpg = gnupg.GPG()
        record = get_first_secure_response(results)
        key = record['rdata']['rdata_raw']
        armored = string.join(['-----BEGIN PGP PUBLIC KEY BLOCK-----',
                               'Version: GnuPG v1.4.9 (Darwin)',
                               base64.b64encode(key),
                               '-----END PGP PUBLIC KEY BLOCK-----'],
                              '\n')
    try:
        import_results = gpg.import_keys(armored)
        fingerprint = import_results.results[0]['fingerprint']
        encrypted = gpg.encrypt('A bunch of text', fingerprint, always_trust=True)
        print str(encrypted)
    except:
        print 'Error: ', sys.exc_info()[0]
        sys.exit(1)

if __name__ == '__main__':
    main()
