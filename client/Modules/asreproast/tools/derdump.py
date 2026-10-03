#!/usr/bin/env python3
"""Parse a DER blob (hex on argv[1], or stdin) and pretty-print the TLV tree.

Used to compare the AS-REQ that the BOF's build_asreq() emits against the one
impacket's canonical encoder emits, field by field, ignoring the two fields
that legitimately vary between runs (nonce and till).

  ./derdump.py <hex>
  ./derdump.py --from-imacket user corp.local
"""
import sys

TAGS = {
    0x01: "BOOLEAN", 0x02: "INTEGER", 0x03: "BIT STRING", 0x04: "OCTET STRING",
    0x05: "NULL", 0x06: "OID", 0x0A: "ENUM", 0x10: "SEQUENCE", 0x11: "SET",
    0x17: "UTCTime", 0x18: "GeneralizedTime", 0x1B: "GeneralString",
    0x1C: "UniversalString", 0x1E: "BMPString", 0x1F: "UTF8String",
    0x0C: "UTF8String", 0x13: "PrintableString", 0x14: "TeletexString",
    0x16: "IA5String",
}


def name(tag):
    if tag in TAGS:
        return TAGS[tag]
    if 0xA0 <= tag <= 0xBF:
        return "CTX [%d]" % (tag & 0x1F)
    if 0x60 <= tag <= 0x7F:
        return "APP [%d]" % (tag & 0x1F)
    if 0x80 <= tag <= 0x9F:
        return "CTX-primitive [%d]" % (tag & 0x1F)
    return "TAG 0x%02x" % tag


def walk(buf, pos, end, depth, out):
    while pos < end:
        tag = buf[pos]
        pos += 1
        ln = buf[pos]
        pos += 1
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(buf[pos:pos + n], "big")
            pos += n
        if pos + ln > end:
            out.append("%s%s len=%d TRUNCATED" % ("  " * depth, name(tag), ln))
            return
        body = buf[pos:pos + ln]
        constructed = bool(tag & 0x20)
        if constructed and ln:
            out.append("%s%s len=%d {" % ("  " * depth, name(tag), ln))
            walk(buf, pos, pos + ln, depth + 1, out)
            out.append("%s}" % ("  " * depth))
        else:
            out.append("%s%s len=%d = %s" % (
                "  " * depth, name(tag), ln, body.hex()))
        pos += ln


def from_imacket(user, realm):
    """Encode the canonical AS-REQ with impacket.

    Modern pyasn1 (>=0.5) refuses the old "assign an object to a NamedType"
    idiom ("NamedTypes can cast only scalar values"), and context-tagged
    fields must be entered through noValue before descending into them.
    This mirrors impacket's own getTGT.py.
    """
    from impacket.krb5.asn1 import AS_REQ
    from impacket.krb5.constants import PrincipalNameType
    from impacket.krb5.types import KerberosTime
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.type.univ import noValue
    import datetime

    realm = realm.upper()
    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = 10

    body = as_req["req-body"]

    # Bit 1 = forwardable, bit 8 = renewable, bit 15 = canonicalize (RFC 6806).
    body["kdc-options"] = noValue
    body["kdc-options"]["forwardable"] = True
    body["kdc-options"]["renewable"] = True
    body["kdc-options"]["canonicalize"] = True

    body["cname"] = noValue
    body["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
    body["cname"]["name-string"] = noValue
    body["cname"]["name-string"][0] = user

    body["realm"] = realm

    body["sname"] = noValue
    body["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
    body["sname"]["name-string"] = noValue
    body["sname"]["name-string"][0] = "krbtgt"
    body["sname"]["name-string"][1] = realm

    till = KerberosTime.to_asn1(datetime.datetime(2037, 9, 13, 8, 5, 10))
    body["till"] = till
    body["rtime"] = till
    body["nonce"] = 0x34026CCD

    body["etype"] = noValue
    for _i, _e in enumerate((23, 17, 18)):
        body["etype"][_i] = _e

    return der_encoder.encode(as_req)


def main():
    if sys.argv[1] == "--from-imacket":
        raw = from_imacket(sys.argv[2], sys.argv[3])
    else:
        raw = bytes.fromhex(sys.argv[1].strip())
    out = []
    walk(raw, 0, len(raw), 0, out)
    print("\n".join(out))


if __name__ == "__main__":
    main()
