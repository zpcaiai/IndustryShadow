from __future__ import annotations

import datetime as dt
import hashlib
import stat
import subprocess
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, utc_now

from .evidence import GateCheck, GateEvidence, complete


class CertificateAuthorityProbe:
    """Validate externally issued OPC UA leaf chains, purpose, URI SAN, and revocation."""

    def __init__(
        self,
        *,
        server_certificate: str | Path,
        client_certificate: str | Path,
        ca_bundle: str | Path,
        server_application_uri: str,
        client_application_uri: str,
        expected_server_fingerprint: str,
        expected_client_fingerprint: str,
        next_server_certificate: str | Path | None = None,
        next_client_certificate: str | Path | None = None,
        expected_next_server_fingerprint: str | None = None,
        expected_next_client_fingerprint: str | None = None,
        crl_file: str | Path | None = None,
        minimum_validity_days: int = 30,
        openssl_binary: str = "openssl",
        client_private_key: str | Path | None = None,
        next_client_private_key: str | Path | None = None,
        require_client_key_match: bool = False,
    ) -> None:
        self.server_certificate = Path(server_certificate)
        self.client_certificate = Path(client_certificate)
        self.ca_bundle = Path(ca_bundle)
        self.crl_file = Path(crl_file) if crl_file else None
        self.next_server_certificate = (
            Path(next_server_certificate) if next_server_certificate else None
        )
        self.next_client_certificate = (
            Path(next_client_certificate) if next_client_certificate else None
        )
        self.server_application_uri = server_application_uri
        self.client_application_uri = client_application_uri
        self.expected_server_fingerprint = self._normalise_fingerprint(expected_server_fingerprint)
        self.expected_client_fingerprint = self._normalise_fingerprint(expected_client_fingerprint)
        self.expected_next_server_fingerprint = self._normalise_fingerprint(
            expected_next_server_fingerprint
        )
        self.expected_next_client_fingerprint = self._normalise_fingerprint(
            expected_next_client_fingerprint
        )
        self.minimum_validity_days = minimum_validity_days
        self.openssl_binary = openssl_binary
        self.client_private_key = Path(client_private_key) if client_private_key else None
        self.next_client_private_key = (
            Path(next_client_private_key) if next_client_private_key else None
        )
        self.require_client_key_match = require_client_key_match
        for path in (
            self.server_certificate,
            self.client_certificate,
            self.ca_bundle,
            self.next_server_certificate,
            self.next_client_certificate,
            self.client_private_key,
            self.next_client_private_key,
        ):
            if path is None:
                continue
            if not path.is_file():
                raise DomainError(
                    "CERTIFICATE_FILE_MISSING", "required certificate file is missing"
                )
        if self.crl_file and not self.crl_file.is_file():
            raise DomainError("CRL_FILE_MISSING", "configured CRL file is missing")
        for key_path in (self.client_private_key, self.next_client_private_key):
            if key_path and stat.S_IMODE(key_path.stat().st_mode) & 0o077:
                raise DomainError(
                    "CERTIFICATE_KEY_PERMISSIONS_INVALID",
                    "client private key must not be accessible to group or other users",
                )
        if require_client_key_match and not (
            self.client_private_key and self.next_client_private_key
        ):
            raise DomainError(
                "CERTIFICATE_KEY_REQUIRED", "current and next client private keys are required"
            )

    @staticmethod
    def _normalise_fingerprint(value: str | None) -> str:
        return "" if value is None else value.replace(":", "").strip().lower()

    @staticmethod
    def _load(path: Path) -> Any:
        try:
            from cryptography import x509
        except ImportError as error:
            raise DomainError(
                "CRYPTOGRAPHY_DEPENDENCY_UNAVAILABLE", "cryptography is required", status=503
            ) from error
        data = path.read_bytes()
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            return x509.load_der_x509_certificate(data)

    def _verify_chain(self, certificate: Path, purpose: str) -> bool:
        command = [
            self.openssl_binary,
            "verify",
            "-purpose",
            purpose,
            "-CAfile",
            str(self.ca_bundle),
        ]
        if self.crl_file:
            command.extend(("-CRLfile", str(self.crl_file), "-crl_check_all"))
        command.append(str(certificate))
        completed = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        return completed.returncode == 0

    def _crl_current(self) -> bool:
        if self.crl_file is None:
            return False
        from cryptography import x509

        value = self.crl_file.read_bytes()
        try:
            crl = x509.load_pem_x509_crl(value)
        except ValueError:
            crl = x509.load_der_x509_crl(value)
        now = dt.datetime.now(dt.UTC)
        return crl.next_update_utc is not None and crl.last_update_utc <= now <= crl.next_update_utc

    @staticmethod
    def _properties(
        certificate: Any, application_uri: str, expected_usage: Any
    ) -> dict[str, Any]:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
        from cryptography.x509.oid import ExtensionOID

        now = dt.datetime.now(dt.UTC)
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        try:
            san = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            uri_present = application_uri in san.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound:
            uri_present = False
        try:
            basic = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            leaf = not basic.ca
        except x509.ExtensionNotFound:
            leaf = True
        try:
            extended = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            purpose_present = expected_usage in extended
        except x509.ExtensionNotFound:
            purpose_present = False
        try:
            usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            signing_allowed = usage.digital_signature and (
                usage.key_encipherment or usage.key_agreement
            )
        except x509.ExtensionNotFound:
            signing_allowed = False
        public_key = certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_bits = public_key.key_size
            strong_key = key_bits >= 2048
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_bits = public_key.key_size
            strong_key = key_bits >= 256
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_bits = public_key.key_size
            strong_key = key_bits >= 2048
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key_bits = 255 if isinstance(public_key, ed25519.Ed25519PublicKey) else 448
            strong_key = True
        else:
            key_bits = 0
            strong_key = False
        signature_hash = certificate.signature_hash_algorithm
        strong_signature = signature_hash is None or signature_hash.name not in {"md5", "sha1"}
        return {
            "currently_valid": not_before <= now <= not_after,
            "validity_days": max(0, int((not_after - now).total_seconds() // 86400)),
            "uri_present": uri_present,
            "leaf": leaf,
            "purpose_present": purpose_present,
            "key_usage_valid": signing_allowed,
            "key_bits": key_bits,
            "strong_crypto": strong_key and strong_signature,
            "fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
        }

    @staticmethod
    def _key_matches(certificate: Any, key_path: Path | None) -> bool:
        if key_path is None:
            return False
        from cryptography.hazmat.primitives import serialization

        try:
            private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        except (TypeError, ValueError):
            return False
        certificate_key = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_key = private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return certificate_key == private_key

    def run(self) -> GateEvidence:
        started = utc_now()
        from cryptography.x509.oid import ExtendedKeyUsageOID

        server_certificate = self._load(self.server_certificate)
        client_certificate = self._load(self.client_certificate)
        server = self._properties(
            server_certificate, self.server_application_uri, ExtendedKeyUsageOID.SERVER_AUTH
        )
        client = self._properties(
            client_certificate, self.client_application_uri, ExtendedKeyUsageOID.CLIENT_AUTH
        )
        next_server = (
            self._properties(
                self._load(self.next_server_certificate),
                self.server_application_uri,
                ExtendedKeyUsageOID.SERVER_AUTH,
            )
            if self.next_server_certificate
            else None
        )
        next_client_certificate = (
            self._load(self.next_client_certificate) if self.next_client_certificate else None
        )
        next_client = (
            self._properties(
                next_client_certificate,
                self.client_application_uri,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            if next_client_certificate
            else None
        )
        rotation_material_present = bool(
            next_server
            and next_client
            and self.expected_next_server_fingerprint
            and self.expected_next_client_fingerprint
        )
        checks = (
            GateCheck("server_chain", self._verify_chain(self.server_certificate, "sslserver")),
            GateCheck("client_chain", self._verify_chain(self.client_certificate, "sslclient")),
            GateCheck("revocation_checked", self._crl_current()),
            GateCheck(
                "server_identity",
                server["currently_valid"]
                and server["leaf"]
                and server["uri_present"]
                and server["strong_crypto"]
                and server["purpose_present"]
                and server["key_usage_valid"]
                and server["fingerprint"] == self.expected_server_fingerprint
                and server["validity_days"] >= self.minimum_validity_days,
                {"validity_days": server["validity_days"]},
            ),
            GateCheck(
                "client_identity",
                client["currently_valid"]
                and client["leaf"]
                and client["uri_present"]
                and client["strong_crypto"]
                and client["purpose_present"]
                and client["key_usage_valid"]
                and client["fingerprint"] == self.expected_client_fingerprint
                and client["validity_days"] >= self.minimum_validity_days,
                {"validity_days": client["validity_days"]},
            ),
            GateCheck("rotation_material_present", rotation_material_present),
            GateCheck(
                "client_private_key_matches",
                self._key_matches(client_certificate, self.client_private_key)
                or not self.require_client_key_match,
            ),
            GateCheck(
                "next_client_private_key_matches",
                self._key_matches(next_client_certificate, self.next_client_private_key)
                if next_client_certificate and self.require_client_key_match
                else not self.require_client_key_match,
            ),
            GateCheck(
                "next_server_chain",
                bool(
                    self.next_server_certificate
                    and self._verify_chain(self.next_server_certificate, "sslserver")
                ),
            ),
            GateCheck(
                "next_client_chain",
                bool(
                    self.next_client_certificate
                    and self._verify_chain(self.next_client_certificate, "sslclient")
                ),
            ),
            GateCheck(
                "next_server_identity",
                bool(
                    next_server
                    and next_server["currently_valid"]
                    and next_server["leaf"]
                    and next_server["uri_present"]
                    and next_server["strong_crypto"]
                    and next_server["purpose_present"]
                    and next_server["key_usage_valid"]
                    and next_server["fingerprint"] == self.expected_next_server_fingerprint
                    and next_server["fingerprint"] != server["fingerprint"]
                    and next_server["validity_days"] >= self.minimum_validity_days
                ),
                {"validity_days": next_server["validity_days"] if next_server else 0},
            ),
            GateCheck(
                "next_client_identity",
                bool(
                    next_client
                    and next_client["currently_valid"]
                    and next_client["leaf"]
                    and next_client["uri_present"]
                    and next_client["strong_crypto"]
                    and next_client["purpose_present"]
                    and next_client["key_usage_valid"]
                    and next_client["fingerprint"] == self.expected_next_client_fingerprint
                    and next_client["fingerprint"] != client["fingerprint"]
                    and next_client["validity_days"] >= self.minimum_validity_days
                ),
                {"validity_days": next_client["validity_days"] if next_client else 0},
            ),
        )
        return complete(
            "external_ca",
            started_at=started,
            coordinates={
                "server_application_uri": self.server_application_uri,
                "client_application_uri": self.client_application_uri,
                "ca_bundle_digest": hashlib.sha256(self.ca_bundle.read_bytes()).hexdigest(),
                "crl_digest": (
                    hashlib.sha256(self.crl_file.read_bytes()).hexdigest()
                    if self.crl_file
                    else "missing"
                ),
            },
            checks=checks,
            metrics={
                "server_validity_days": server["validity_days"],
                "client_validity_days": client["validity_days"],
                "server_key_bits": server["key_bits"],
                "client_key_bits": client["key_bits"],
                "next_server_validity_days": (next_server["validity_days"] if next_server else 0),
                "next_client_validity_days": (next_client["validity_days"] if next_client else 0),
            },
            limitations=(
                ()
                if self.crl_file and rotation_material_present
                else ("external_ca_rotation_or_revocation_material_incomplete",)
            ),
        )
