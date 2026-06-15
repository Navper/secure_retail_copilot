"""
auth.py — Módulo de autenticación para Secure Retail AI Copilot.

Centraliza la verificación de contraseñas del panel de administración.

Estrategia:
  - Si ADMIN_PASSWORD_HASH está definido en .env → compara contra el hash SHA256.
  - Si solo ADMIN_PASSWORD está definido → comparación directa con hmac.compare_digest
    (timing-safe) + aviso en consola para que el admin configure el hash.
  - Nunca compara con == para evitar timing attacks.

Uso:
    from auth import verify_admin_password
    if verify_admin_password(input_password):
        # acceso concedido

Para generar el hash de una contraseña:
    python -c "from auth import hash_password; print(hash_password('mi_password_segura'))"
"""

import hashlib
import hmac
import os


# Salt estático leído del entorno. Si no existe, usamos un valor fijo de fallback
# (solo para compatibilidad; en producción SIEMPRE debe estar en .env).
_SALT = os.getenv("PASSWORD_SALT", "secure_retail_default_salt_v1")


def hash_password(plain: str) -> str:
    """
    Genera el hash SHA256 de una contraseña con salt.

    Args:
        plain: Contraseña en texto plano.

    Returns:
        Hash hexadecimal listo para guardar en .env como ADMIN_PASSWORD_HASH.
    """
    salted = f"{_SALT}:{plain}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


def verify_admin_password(input_password: str) -> bool:
    """
    Verifica la contraseña de administrador de forma timing-safe.

    Primero busca ADMIN_PASSWORD_HASH en el entorno (modo seguro).
    Si no existe, cae back a ADMIN_PASSWORD en texto plano con aviso.

    Args:
        input_password: Contraseña introducida por el usuario en la UI.

    Returns:
        True si la contraseña es correcta, False en caso contrario.
    """
    stored_hash = os.getenv("ADMIN_PASSWORD_HASH", "")

    if stored_hash:
        # Modo seguro: comparar hash vs hash (timing-safe)
        input_hash = hash_password(input_password)
        return hmac.compare_digest(stored_hash, input_hash)
    else:
        # Fallback: comparación directa timing-safe contra texto plano
        # (emite advertencia para que el admin configure el hash)
        plain_password = os.getenv("ADMIN_PASSWORD", "admin123")
        print(
            "[AUTH WARNING] ADMIN_PASSWORD_HASH no está configurado. "
            "Ejecuta: python -c \"from auth import hash_password; print(hash_password('tu_password'))\" "
            "y añade el resultado como ADMIN_PASSWORD_HASH en tu .env"
        )
        return hmac.compare_digest(plain_password, input_password)
