#!/usr/bin/env python3
"""
Build, sign, and POST a SAMLResponse to the broker's SAML SP ACS endpoint.

Runs inside a python:3.12-slim Docker container — see test-saml-inbound.sh.
Loads the test IdP's PKCS12 keystore, builds a SAML 2.0 Response with a
signed Assertion (RSA-SHA256, exclusive c14n), base64-encodes, POSTs to the
broker, and prints the response.
"""
import argparse
import base64
import sys
import uuid
from datetime import datetime, timedelta, timezone

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
from lxml import etree
from signxml import XMLSigner, methods

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"


def saml(tag):
    return f"{{{NS_SAML}}}{tag}"


def samlp(tag):
    return f"{{{NS_SAMLP}}}{tag}"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_response(args, now):
    not_before = now - timedelta(minutes=1)
    not_on_or_after = now + timedelta(minutes=5)
    response_id = "_" + uuid.uuid4().hex
    assertion_id = "_" + uuid.uuid4().hex

    response = etree.Element(
        samlp("Response"),
        nsmap={"samlp": NS_SAMLP, "saml": NS_SAML},
        attrib={
            "ID": response_id,
            "Version": "2.0",
            "IssueInstant": iso(now),
            "Destination": args.acs_url,
        },
    )
    etree.SubElement(response, saml("Issuer")).text = args.idp_entity_id

    status = etree.SubElement(response, samlp("Status"))
    etree.SubElement(
        status,
        samlp("StatusCode"),
        attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
    )

    assertion = etree.SubElement(
        response,
        saml("Assertion"),
        attrib={
            "ID": assertion_id,
            "Version": "2.0",
            "IssueInstant": iso(now),
        },
    )
    etree.SubElement(assertion, saml("Issuer")).text = args.idp_entity_id

    subject = etree.SubElement(assertion, saml("Subject"))
    etree.SubElement(
        subject,
        saml("NameID"),
        attrib={"Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"},
    ).text = args.user_id
    sub_conf = etree.SubElement(
        subject,
        saml("SubjectConfirmation"),
        attrib={"Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer"},
    )
    etree.SubElement(
        sub_conf,
        saml("SubjectConfirmationData"),
        attrib={
            "Recipient": args.acs_url,
            "NotOnOrAfter": iso(not_on_or_after),
        },
    )

    conditions = etree.SubElement(
        assertion,
        saml("Conditions"),
        attrib={
            "NotBefore": iso(not_before),
            "NotOnOrAfter": iso(not_on_or_after),
        },
    )
    aud_restriction = etree.SubElement(conditions, saml("AudienceRestriction"))
    etree.SubElement(aud_restriction, saml("Audience")).text = args.sp_entity_id

    authn_stmt = etree.SubElement(
        assertion, saml("AuthnStatement"), attrib={"AuthnInstant": iso(now)}
    )
    authn_ctx = etree.SubElement(authn_stmt, saml("AuthnContext"))
    etree.SubElement(authn_ctx, saml("AuthnContextClassRef")).text = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )

    return response, assertion, assertion_id


def load_pkcs12(path, password):
    with open(path, "rb") as f:
        priv_key, cert, _ = pkcs12.load_key_and_certificates(f.read(), password.encode())
    cert_pem = cert.public_bytes(Encoding.PEM)
    priv_pem = priv_key.private_bytes(
        encoding=Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return priv_pem, cert_pem


def sign_assertion(assertion, assertion_id, priv_pem, cert_pem):
    """Sign the Assertion with enveloped XML-DSig (RSA-SHA256, exc-c14n)."""
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(
        assertion,
        key=priv_pem,
        cert=cert_pem,
        reference_uri=f"#{assertion_id}",
    )
    # SAML schema requires Signature to be the *second* child of Assertion
    # (right after Issuer). signxml appends it; move it.
    sig = signed.find(f"{{{NS_DS}}}Signature")
    if sig is not None:
        signed.remove(sig)
        issuer = signed.find(saml("Issuer"))
        issuer.addnext(sig)
    return signed


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--acs-url", required=True)
    p.add_argument("--idp-entity-id", required=True)
    p.add_argument("--sp-entity-id", required=True)
    p.add_argument("--state-code", required=True)
    p.add_argument("--keystore", required=True)
    p.add_argument("--keystore-pass", required=True)
    p.add_argument("--alias", required=True)
    p.add_argument("--user-id", default="DLR011001703")
    args = p.parse_args()

    priv_pem, cert_pem = load_pkcs12(args.keystore, args.keystore_pass)

    now = datetime.now(timezone.utc)
    response, assertion, assertion_id = build_response(args, now)
    signed_assertion = sign_assertion(assertion, assertion_id, priv_pem, cert_pem)
    response.replace(assertion, signed_assertion)

    response_xml = etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    saml_response_b64 = base64.b64encode(response_xml).decode("ascii")

    print(f"[client] POST    {args.acs_url}")
    print(f"[client] user_id={args.user_id}  assertion_id={assertion_id}")
    print(f"[client] RelayState={args.state_code}")
    print()

    resp = requests.post(
        args.acs_url,
        data={"SAMLResponse": saml_response_b64, "RelayState": args.state_code},
        allow_redirects=False,
        timeout=15,
    )

    print(f"[broker] HTTP {resp.status_code}  Content-Type: {resp.headers.get('content-type','?')}")
    print()
    body = resp.text
    if len(body) > 2000:
        body = body[:2000] + f"\n... ({len(resp.text) - 2000} more chars)"
    print(body)
    print()

    ok = resp.status_code == 200 and (
        "htxtToken" in resp.text or "SAMLResponse" in resp.text
    )
    if ok:
        print("[result] ✓ Broker accepted the SAML assertion and emitted auto-submit HTML.")
        sys.exit(0)
    else:
        print("[result] ✗ Broker did NOT produce auto-submit HTML.")
        print("[result]   Run: docker compose logs iam-broker | tail -50")
        sys.exit(1)


if __name__ == "__main__":
    main()
