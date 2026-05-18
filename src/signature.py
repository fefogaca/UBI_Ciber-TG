"""Assinatura digital opcional: ECDSA e RSA-PSS."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from src.crypto_config import hash_to_cryptography


def detect_sign_algo(private_key) -> str:
    """
    Inferir algoritmo de assinatura a partir da chave privada carregada.

    :param private_key: instância de ec.EllipticCurvePrivateKey ou rsa.RSAPrivateKey.
    :return: \"ECDSA-P256\", \"ECDSA-P384\" ou \"RSA-PSS\".
    """
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        name = private_key.curve.name
        if name == "secp256r1":
            return "ECDSA-P256"
        if name == "secp384r1":
            return "ECDSA-P384"
        raise ValueError(
            f"Curva ECDSA não suportada para assinatura: {name}. Use P-256 ou P-384."
        )
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RSA-PSS"
    raise TypeError(f"Tipo de chave privada não suportado: {type(private_key)!r}")


def sign_data(private_key_path: str, data: bytes, hash_name: str) -> tuple[bytes, str]:
    """
    Assina o conteúdo `data` (o digest é computado internamente segundo hash_name).

    :param private_key_path: caminho para PEM PKCS8 da chave privada.
    :param data: bytes a assinar (ex.: ficheiro original).
    :param hash_name: SHA256 / SHA384 / SHA512.
    :return: (assinatura, sign_algo para o header).
    """
    pem = Path(private_key_path).read_bytes()
    private_key = load_pem_private_key(pem, password=None)
    algo = detect_sign_algo(private_key)
    hash_algo = hash_to_cryptography(hash_name)

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(data, ec.ECDSA(hash_algo))
    else:
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_algo),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hash_algo,
        )
    return signature, algo


def load_verify_key(path: str):
    """
    Carrega chave pública PEM ou extrai do certificado X.509 PEM.

    :param path: ficheiro PEM.
    :return: chave pública (interfaces EllipticCurvePublicKey ou RSAPublicKey).
    """
    blob = Path(path).read_bytes()
    try:
        return load_pem_public_key(blob)
    except ValueError:
        cert = x509.load_pem_x509_certificate(blob)
        return cert.public_key()


def _sign_algo_matches_key(sign_algo: str, public_key) -> None:
    """Levanta ValueError se sign_algo não for compatível com o tipo da chave."""
    if sign_algo in ("ECDSA-P256", "ECDSA-P384"):
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError(
                f"Incompatibilidade de algoritmo de assinatura: o cabeçalho indica {sign_algo}, "
                "mas a chave de verificação não é ECDSA."
            )
        want = "secp256r1" if sign_algo == "ECDSA-P256" else "secp384r1"
        if public_key.curve.name != want:
            raise ValueError(
                f"Incompatibilidade de algoritmo de assinatura: o cabeçalho indica {sign_algo}, "
                f"mas a curva da chave é {public_key.curve.name}."
            )
    elif sign_algo == "RSA-PSS":
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError(
                "Incompatibilidade de algoritmo de assinatura: o cabeçalho indica RSA-PSS, "
                "mas a chave de verificação não é RSA."
            )
    else:
        raise ValueError(f"sign_algo desconhecido no header: {sign_algo!r}")


def verify_signature(
    verify_key_path: str,
    data: bytes,
    signature: bytes,
    sign_algo: str,
    hash_name: str,
) -> bool:
    """
    Verifica assinatura sobre `data`.

    :param verify_key_path: PEM público ou certificado.
    :param data: mesmo conteúdo que foi assinado no emissor.
    :param signature: bytes da assinatura.
    :param sign_algo: campo do header (ECDSA-P256, ECDSA-P384, RSA-PSS).
    :param hash_name: SHA256 / SHA384 / SHA512.
    :return: True se válida.
    :raises ValueError: incompatibilidade tipo/sign_algo ou verificação falhada.
    """
    public_key = load_verify_key(verify_key_path)
    _sign_algo_matches_key(sign_algo, public_key)
    hash_algo = hash_to_cryptography(hash_name)

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hash_algo))
        else:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hash_algo),
                    salt_length=padding.PSS.DIGEST_LENGTH,
                ),
                hash_algo,
            )
    except InvalidSignature as exc:
        raise ValueError("Verificação de assinatura falhou: assinatura inválida.") from exc
    return True


def fill_sign_algo_from_key_path(private_key_path: str) -> str:
    """Carrega PEM privada e devolve apenas a etiqueta sign_algo (sem assinar)."""
    pem = Path(private_key_path).read_bytes()
    private_key = load_pem_private_key(pem, password=None)
    return detect_sign_algo(private_key)
