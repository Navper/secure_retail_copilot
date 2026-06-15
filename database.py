"""
database.py — Capa de acceso a datos SQLite para Secure Retail AI Copilot.

Responsabilidades:
  - Inicializar la base de datos y migrar desde el CSV existente.
  - Exponer funciones CRUD limpias para el resto de la aplicación.
"""

import os
import sqlite3
import pandas as pd

DB_PATH = os.path.join(os.path.dirname(__file__), "retail.db")
CSV_PATH = os.path.join(os.path.dirname(__file__), "inventory.csv")

# ─────────────────────────────────────────────
# Esquema
# ─────────────────────────────────────────────
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    price       REAL NOT NULL,
    stock       INTEGER NOT NULL,
    category    TEXT NOT NULL DEFAULT 'General'
);
"""

_CREATE_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS conversation_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL,
    user_input    TEXT    NOT NULL,
    response      TEXT,
    blocked       INTEGER NOT NULL DEFAULT 0,
    threat_type   TEXT,
    confidence    REAL,
    latency_ms    INTEGER
);
"""

# Fix #2 — Rate limit persistente en SQLite
_CREATE_RATE_LIMIT_SQL = """
CREATE TABLE IF NOT EXISTS rate_limit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT    NOT NULL,
    timestamp  TEXT    NOT NULL
);
"""

# Índice para acelerar las consultas de ventana deslizante
_CREATE_RATE_LIMIT_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_rate_limit_session_ts
    ON rate_limit_log (session_id, timestamp);
"""


def _get_connection() -> sqlite3.Connection:
    """Retorna una conexión a la base de datos con row_factory habilitado."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────
# Inicialización y migración
# ─────────────────────────────────────────────
def init_db() -> None:
    """
    Crea la base de datos y las tablas si no existen.
    Si la tabla products está vacía y existe el CSV, migra los datos automáticamente.
    """
    with _get_connection() as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.execute(_CREATE_LOGS_SQL)
        conn.execute(_CREATE_RATE_LIMIT_SQL)
        conn.execute(_CREATE_RATE_LIMIT_INDEX_SQL)
        conn.commit()

        # Comprobamos si la tabla ya tiene datos
        count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if count == 0 and os.path.exists(CSV_PATH):
            _migrate_from_csv(conn)


def _migrate_from_csv(conn: sqlite3.Connection) -> None:
    """Importa los productos del CSV existente a SQLite."""
    df = pd.read_csv(CSV_PATH)

    # Normalizar nombres de columnas por si hay variaciones
    df.columns = [c.strip().lower() for c in df.columns]

    # Mapear columnas del CSV al esquema de la BD
    column_map = {
        "product_id": "id",
        "name": "name",
        "description": "description",
        "price": "price",
        "stock": "stock",
    }
    df = df.rename(columns=column_map)

    if "category" not in df.columns:
        df["category"] = "General"

    # Solo las columnas que nos interesan
    df = df[["id", "name", "description", "price", "stock", "category"]]

    df.to_sql("products", conn, if_exists="append", index=False)
    print(f"[database] Migrados {len(df)} productos desde {CSV_PATH}")


# ─────────────────────────────────────────────
# Lectura
# ─────────────────────────────────────────────
def get_all_products() -> pd.DataFrame:
    """Retorna todos los productos como un DataFrame de pandas."""
    with _get_connection() as conn:
        return pd.read_sql_query("SELECT * FROM products ORDER BY id", conn)


def get_product_by_id(product_id: str) -> dict | None:
    """Retorna un producto concreto como dict, o None si no existe."""
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        return dict(row) if row else None


# ─────────────────────────────────────────────
# Escritura
# ─────────────────────────────────────────────
def add_product(product_id: str, name: str, description: str,
                price: float, stock: int, category: str = "General") -> None:
    """Inserta un nuevo producto en la base de datos."""
    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO products (id, name, description, price, stock, category)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (product_id, name, description, price, stock, category),
        )
        conn.commit()


def update_product(product_id: str, name: str, description: str,
                   price: float, stock: int, category: str) -> bool:
    """
    Actualiza un producto existente.
    Retorna True si se modificó alguna fila, False si el ID no existe.
    """
    with _get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE products
            SET name = ?, description = ?, price = ?, stock = ?, category = ?
            WHERE id = ?
            """,
            (name, description, price, stock, category, product_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def delete_product(product_id: str) -> bool:
    """
    Elimina un producto por ID.
    Retorna True si se eliminó, False si no existía.
    """
    with _get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM products WHERE id = ?", (product_id,)
        )
        conn.commit()
        return cursor.rowcount > 0


def get_next_product_id() -> str:
    """Genera el siguiente ID de producto en formato PROD###."""
    with _get_connection() as conn:
        # Obtenemos el mayor número existente para auto-incrementar
        row = conn.execute(
            "SELECT MAX(CAST(REPLACE(id, 'PROD', '') AS INTEGER)) FROM products WHERE id LIKE 'PROD%'"
        ).fetchone()
        last_num = row[0] if row[0] is not None else 0
        return f"PROD{last_num + 1:03d}"


# ─────────────────────────────────────────────
# Conversation Logs (Fase 2 — Seguridad)
# ─────────────────────────────────────────────
def log_interaction(
    session_id: str,
    user_input: str,
    response: str | None,
    blocked: bool,
    threat_type: str | None = None,
    confidence: float | None = None,
    latency_ms: int | None = None,
) -> None:
    """
    Registra una interacción (bloqueada o no) en la tabla conversation_logs.

    Args:
        session_id:   ID único de la sesión de Streamlit.
        user_input:   Texto introducido por el usuario.
        response:     Respuesta mostrada al usuario (None si se bloqueó antes del LLM).
        blocked:      True si la interacción fue bloqueada por algún guard.
        threat_type:  Tipo de amenaza detectada (o None).
        confidence:   Nivel de confianza del detector (0.0–1.0).
        latency_ms:   Tiempo total de procesamiento en milisegundos.
    """
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()

    with _get_connection() as conn:
        conn.execute(
            """
            INSERT INTO conversation_logs
                (session_id, timestamp, user_input, response, blocked, threat_type, confidence, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, timestamp, user_input, response,
             1 if blocked else 0, threat_type, confidence, latency_ms),
        )
        conn.commit()


def get_logs(
    limit: int = 200,
    only_flagged: bool = False,
    threat_filter: str | None = None,
) -> pd.DataFrame:
    """
    Retorna los logs de conversación como DataFrame.

    Args:
        limit:         Número máximo de registros a retornar (los más recientes primero).
        only_flagged:  Si True, solo devuelve interacciones bloqueadas.
        threat_filter: Si se especifica, filtra por tipo de amenaza.

    Returns:
        DataFrame ordenado por timestamp descendente.
    """
    # Fix #6: SQL completamente parametrizado, sin f-strings con input externo
    conditions = []
    params: list = []

    if only_flagged:
        conditions.append("blocked = 1")
    if threat_filter:
        # threat_filter viene de un selectbox interno — validamos igualmente
        allowed_threats = {
            "jailbreak", "prompt_injection", "system_prompt_leak",
            "off_topic", "output_leak", "rate_limit", "input_too_long",
        }
        if threat_filter in allowed_threats:
            conditions.append("threat_type = ?")
            params.append(threat_filter)

    # Construimos la cláusula WHERE solo con condiciones permitidas (sin input directo)
    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    with _get_connection() as conn:
        # La query usa ? para todos los valores; where_clause solo contiene
        # literales internos ('blocked = 1', 'threat_type = ?'), no datos de usuario.
        query = f"SELECT * FROM conversation_logs {where_clause} ORDER BY id DESC LIMIT ?"  # noqa: S608
        return pd.read_sql_query(query, conn, params=params)


def get_security_stats() -> dict:
    """
    Retorna métricas de seguridad agregadas para el dashboard.

    Returns:
        Dict con claves: total, blocked, block_rate, avg_latency_ms,
        threat_breakdown (dict threat_type -> count).
    """
    with _get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM conversation_logs").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM conversation_logs WHERE blocked = 1").fetchone()[0]
        avg_lat = conn.execute(
            "SELECT AVG(latency_ms) FROM conversation_logs WHERE latency_ms IS NOT NULL"
        ).fetchone()[0]

        threat_rows = conn.execute(
            "SELECT threat_type, COUNT(*) as cnt FROM conversation_logs "
            "WHERE threat_type IS NOT NULL GROUP BY threat_type ORDER BY cnt DESC"
        ).fetchall()

    threat_breakdown = {row[0]: row[1] for row in threat_rows}

    return {
        "total": total,
        "blocked": blocked,
        "block_rate": round(blocked / total * 100, 1) if total > 0 else 0.0,
        "avg_latency_ms": round(avg_lat) if avg_lat else 0,
        "threat_breakdown": threat_breakdown,
    }


def clear_logs() -> int:
    """Elimina todos los logs de conversación. Retorna el número de filas eliminadas."""
    with _get_connection() as conn:
        cursor = conn.execute("DELETE FROM conversation_logs")
        conn.commit()
        return cursor.rowcount


# ─────────────────────────────────────────────
# Rate Limit persistente (Fix #2)
# ─────────────────────────────────────────────
def record_rate_event(session_id: str) -> None:
    """
    Registra un evento de mensaje en la tabla rate_limit_log.
    Persiste entre reinicios de Streamlit a diferencia del dict en memoria.
    """
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()
    with _get_connection() as conn:
        conn.execute(
            "INSERT INTO rate_limit_log (session_id, timestamp) VALUES (?, ?)",
            (session_id, timestamp),
        )
        conn.commit()


def count_recent_messages(session_id: str, window_seconds: int = 60) -> int:
    """
    Cuenta cuántos mensajes ha enviado session_id en los últimos window_seconds.

    Args:
        session_id: ID de la sesión de Streamlit.
        window_seconds: Tamaño de la ventana deslizante en segundos.

    Returns:
        Número de mensajes en la ventana.
    """
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM rate_limit_log WHERE session_id = ? AND timestamp > ?",
            (session_id, cutoff),
        ).fetchone()
        return row[0] if row else 0


def cleanup_rate_limit_log(keep_seconds: int = 300) -> int:
    """
    Elimina entradas antiguas del rate_limit_log para evitar crecimiento indefinido.
    Mantiene solo los últimos keep_seconds segundos (default: 5 minutos).

    Returns:
        Número de filas eliminadas.
    """
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=keep_seconds)).isoformat()
    with _get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM rate_limit_log WHERE timestamp < ?",
            (cutoff,),
        )
        conn.commit()
        return cursor.rowcount
