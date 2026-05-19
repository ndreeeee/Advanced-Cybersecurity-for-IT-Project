import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# OID per simulare l'attestazione hardware TPM (Standard Private Enterprise)
TPM_OID = ObjectIdentifier("1.3.6.1.4.1.9999.1")

def generate_pki():
    base_dir = "certs"
    os.makedirs(base_dir, exist_ok=True)
    
    # 1. GENERAZIONE CA
    print("[PKI] Generazione Root CA...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"ZTA Hospital Trust Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ZTA Projects 2026"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    
    with open(f"{base_dir}/ca.crt", "wb") as f: f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(f"{base_dir}/ca.key", "wb") as f: f.write(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    # 2. GENERAZIONE CERTIFICATO ENVOY
    print("[PKI] Generazione Certificato Envoy...")
    generate_leaf(base_dir, "envoy", "zta-envoy", ca_cert, ca_key)

    # 3. GENERAZIONE CERTIFICATO ALICE (CON TPM)
    print("[PKI] Generazione Certificato Alice (HARDWARE-BACKED)...")
    generate_leaf(base_dir, "alice", "employee-alice", ca_cert, ca_key, has_tpm=True)

    # 4. GENERAZIONE CERTIFICATO BOB (STANDARD)
    print("[PKI] Generazione Certificato Bob (SOFTWARE-ONLY)...")
    generate_leaf(base_dir, "bob", "employee-bob", ca_cert, ca_key, has_tpm=False)

    print("\n[PKI] Success: PKI generated in 'certs/' folder")

def generate_leaf(base_dir, name, cn, ca_cert, ca_key, has_tpm=False):
    print(f"  [PKI] Generating leaf: {name} (CN={cn}, TPM={has_tpm})...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    spiffe_id = f"spiffe://zta.hospital/ns/default/sa/client-{name}"
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    
    # Add SPIFFE
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
        critical=False
    )
    
    # Add TPM
    if has_tpm:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(TPM_OID, b"TPM-VERIFIED-HARDWARE-ROOT-OF-TRUST-PCR0-OK"),
            critical=False
        )
    
    cert = builder.sign(ca_key, hashes.SHA256())
    print(f"    - Certificate signed successfully (Extensions: {len(cert.extensions)})")
    
    with open(f"{base_dir}/{name}.crt", "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(f"{base_dir}/{name}.key", "wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    
    # Crea file combinato (CERT + KEY) per pymongo e altri tool
    with open(f"{base_dir}/{name}_combined.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

if __name__ == "__main__":
    generate_pki()
