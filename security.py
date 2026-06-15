"""
security.py — Capa de seguridad multicapa para Secure Retail AI Copilot.

Proporciona tres mecanismos de defensa independientes del LLM:
  1. InputGuard   — analiza el input del usuario ANTES de que llegue al RAG.
  2. OutputGuard  — filtra la respuesta del LLM ANTES de mostrarla al usuario.
  3. RateLimiter  — limita el número de mensajes por sesión por minuto.

Diseño:
  - Sin dependencias de ML externas (solo regex + heurísticas léxicas).
  - Rápido: el análisis debe completarse en < 5ms para no añadir latencia perceptible.
  - Explicable: cada bloqueo tiene un threat_type y confidence documentados.

Mejoras de seguridad (v2):
  - Normalización de texto antes del análisis: elimina espaciado, homoglifos unicode
    y leet speak para evitar bypass triviales.
  - Límite de longitud de input: rechaza inputs > MAX_INPUT_LENGTH caracteres.
  - Rate limiter delegado a SQLite para persistencia entre reinicios (via database.py).
"""

import os
import re
import time
import unicodedata
import threading
from dataclasses import dataclass


# ─────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────
MAX_INPUT_LENGTH = int(os.getenv("MAX_INPUT_LENGTH", "2000"))


# ─────────────────────────────────────────────
# Resultado del análisis de seguridad
# ─────────────────────────────────────────────
@dataclass
class GuardResult:
    blocked: bool
    threat_type: str | None = None   # "jailbreak" | "prompt_injection" | "system_prompt_leak" | "off_topic" | "output_leak" | "input_too_long" | None
    confidence: float = 0.0           # 0.0 – 1.0
    safe_response: str | None = None  # respuesta fija predefinida si está bloqueado


# ─────────────────────────────────────────────
# Respuestas seguras predefinidas (no generadas por el LLM)
# ─────────────────────────────────────────────
_SAFE_RESPONSES = {
    "jailbreak": (
        "Entiendo tu mensaje, pero no puedo ayudarte con eso. "
        "Estoy aquí exclusivamente para asistirte con los productos de Secure Retail. "
        "¿En qué producto puedo ayudarte hoy?"
    ),
    "prompt_injection": (
        "Lo siento, no puedo procesar ese tipo de instrucciones. "
        "¿Te puedo ayudar con información sobre alguno de nuestros productos?"
    ),
    "system_prompt_leak": (
        "No puedo compartir información sobre mi configuración interna. "
        "Si tienes alguna pregunta sobre nuestro catálogo, estaré encantado de ayudarte."
    ),
    "off_topic": (
        "Lo siento, solo puedo ayudarte con los productos, stock y recomendaciones de Secure Retail."
    ),
    "rate_limit": (
        "Has enviado demasiados mensajes en poco tiempo. "
        "Por favor, espera un momento antes de continuar."
    ),
    "output_leak": (
        "Lo siento, no puedo proporcionar esa información. "
        "¿Hay algo más en lo que pueda ayudarte con nuestro catálogo?"
    ),
    "input_too_long": (
        "Tu mensaje es demasiado largo. Por favor, formula tu pregunta de forma más concisa "
        "(máximo 2000 caracteres)."
    ),
}


# ─────────────────────────────────────────────
# Normalización de texto (Fix #1 y #7)
# ─────────────────────────────────────────────

# Tabla de leet speak básico
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "@": "a",
})


def _normalize(text: str) -> str:
    """
    Normaliza el texto de entrada para dificultar bypass del análisis de seguridad.

    Pasos aplicados en orden:
      1. Normalización NFKD: convierte homoglifos unicode a su equivalente ASCII
         (ej: 'Сomo' cirílico → 'Como' latino, 'ｉgnora' fullwidth → 'ignora').
      2. Eliminación de diacríticos residuales (letras compuestas → base).
      3. Decodificación de leet speak básico (1 → i, @ → a, etc.).
      4. Colapso de espacios entre caracteres individuales
         (ej: 'i g n o r a' → 'ignora').
      5. Conversión a minúsculas.

    Args:
        text: Texto original del usuario.

    Returns:
        Texto normalizado listo para el análisis de patrones.
    """
    # Paso 1: NFKD descompone caracteres unicode compuestos
    normalized = unicodedata.normalize("NFKD", text)

    # Paso 2: Eliminar caracteres de categoría "Mn" (diacríticos/combining marks)
    ascii_text = "".join(c for c in normalized if unicodedata.category(c) != "Mn")

    # Paso 3: Leet speak
    leet_decoded = ascii_text.translate(_LEET_TABLE)

    # Paso 4: Colapsar espaciado entre caracteres sueltos
    # Detecta patrones como "i g n o r a" o "j.a.i.l.b.r.e.a.k"
    # Solo colapsa si hay un patrón sostenido de char-espacio/punto-char
    collapsed = re.sub(r"(?<!\w)((\w[\s._-]){2,}\w)(?!\w)", _collapse_spaced, leet_decoded)

    # Paso 5: Minúsculas
    return collapsed.lower()


def _collapse_spaced(match: re.Match) -> str:
    """Elimina separadores de un grupo de caracteres espaciados."""
    return re.sub(r"[\s._-]", "", match.group(0))


# ─────────────────────────────────────────────
# Patrones de detección de amenazas (INPUT)
# ─────────────────────────────────────────────

# Cada entrada: (patrón_regex, peso_de_confianza)
# Los patrones se aplican sobre el texto NORMALIZADO.
_JAILBREAK_PATTERNS: list[tuple[str, float]] = [
    # Instrucciones directas de evasión
    (r"ignora\s+(las\s+)?instrucciones", 0.95),
    (r"ignora\s+(tus\s+)?(reglas|normas|restricciones)", 0.92),
    (r"olvida\s+(todo|las instrucciones|lo anterior)", 0.95),
    (r"ignore\s+(previous|all|your)\s+instructions", 0.95),
    (r"forget\s+(everything|your instructions)", 0.90),
    (r"bypass\s+(your\s+)?(instructions|rules|restrictions)", 0.95),
    (r"jailbreak", 0.98),
    (r"\bdan\b", 0.85),                                # "Do Anything Now"
    (r"do\s+anything\s+now", 0.90),
    # Cambio de rol
    (r"actua\s+como\s+(si\s+fueras\s+)?(un\s+)?(?!asistente de ventas)", 0.80),
    (r"pretend\s+(you\s+are|to\s+be)", 0.80),
    (r"role.?play", 0.75),
    (r"act\s+as\s+(if\s+you\s+are\s+)?(?!a\s+(retail|sales))", 0.80),
    (r"eres\s+ahora\s+un\s+", 0.85),
    (r"a\s+partir\s+de\s+ahora\s+(eres|seras|actua)", 0.90),
    # Frases de escape clásicas
    (r"(new|nuevo)\s+(prompt|instruccion|instruction)", 0.85),
    (r"override\s+(your\s+)?(system|instructions|rules)", 0.90),
    (r"modo\s+(desarrollador|developer|sin\s+restricciones)", 0.90),
    # Sin restricciones / modo libre
    (r"sin\s+restricciones", 0.85),
    (r"unrestricted\s+mode", 0.90),
    (r"developer\s+mode", 0.88),
    (r"god\s+mode", 0.88),
]

_PROMPT_INJECTION_PATTERNS: list[tuple[str, float]] = [
    # Intentos de inyectar texto de sistema
    (r"system\s*:", 0.85),
    (r"<\s*system\s*>", 0.90),
    (r"<\s*instructions?\s*>", 0.90),
    (r"\[inst\]", 0.85),
    (r"###\s*(system|instruction|context)", 0.80),
    (r'""".*"""', 0.70),                               # triple comillas con contenido
    (r"\n\n(human|assistant|user)\s*:", 0.85),         # simulación de turno de conversación
    (r"<\|im_start\|>", 0.95),                        # tokens de ChatML
    (r"beginning of conversation", 0.85),
    # Nuevos patrones de inyección indirecta
    (r"end\s+of\s+system\s+prompt", 0.92),
    (r"\]\s*\[", 0.70),                                # cierre/apertura de bloques markdown
    (r"---\s*system\s*---", 0.90),
]

_SYSTEM_PROMPT_LEAK_PATTERNS: list[tuple[str, float]] = [
    (r"(cual|que)\s+es\s+tu\s+(prompt|instruccion|system prompt)", 0.90),
    (r"(muestrame|dime|revela)\s+(tu\s+)?(prompt|instrucciones internas|system)", 0.90),
    (r"what\s+(are\s+your\s+)?(system\s+)?(prompt|instructions)", 0.90),
    (r"show\s+(me\s+)?(your\s+)?(prompt|instructions|system)", 0.85),
    (r"repeat\s+(your\s+)?(system|initial)\s+(prompt|instructions)", 0.90),
    (r"print\s+(your\s+)?(system\s+)?prompt", 0.85),
    (r"(texto|contenido)\s+(del\s+)?(prompt|instruccion)\s+(del\s+)?(sistema)", 0.85),
    # Variantes indirectas
    (r"what\s+were\s+you\s+told\s+to\s+do", 0.80),
    (r"(cuales|que)\s+(son|fueron)\s+tus\s+(instrucciones|reglas)", 0.85),
]

_OFF_TOPIC_SEVERE_PATTERNS: list[tuple[str, float]] = [
    # Peticiones de código
    (r"(escribe|genera|crea|write|generate)\s+(un\s+)?(codigo|codigo fuente|script|programa|code)", 0.80),
    (r"(haz|make)\s+(un\s+)?(exploit|malware|virus|hack)", 0.98),
    # Contenido inapropiado
    (r"(contenido|content)\s+(para\s+adultos|adult|sexual|pornografico)", 0.98),
    (r"(drogas|drugs|narcoticos|armas|weapons|explosivos)", 0.85),
    # Petición de datos personales ajenos
    (r"(datos personales|informacion personal)\s+(de\s+)?(otros|clientes|usuarios)", 0.90),
]


def _score_patterns(text: str, patterns: list[tuple[str, float]]) -> float:
    """
    Evalúa el texto contra una lista de patrones regex con peso.
    Devuelve la confianza máxima encontrada (0.0 si ningún patrón coincide).
    Nota: el texto ya debe estar normalizado antes de llamar a esta función.
    """
    max_confidence = 0.0
    for pattern, weight in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            max_confidence = max(max_confidence, weight)
    return max_confidence


# ─────────────────────────────────────────────
# Patrones de detección de fuga en OUTPUT
# ─────────────────────────────────────────────
_OUTPUT_LEAK_PATTERNS: list[tuple[str, float]] = [
    (r"INSTRUCCIONES DE SEGURIDAD", 0.99),
    (r"CUMPLE SIEMPRE ESTAS REGLAS", 0.99),
    (r"CONTEXTO DE PRODUCTOS DISPONIBLES", 0.99),
    (r"system\s*prompt", 0.90),
    (r"mi\s+(prompt|instruccion)\s+(es|dice|indica)", 0.85),
    (r"se\s+me\s+(ha\s+)?instrui?do\s+(a\s+)?(seguir|cumplir|responder)", 0.80),
]


# ─────────────────────────────────────────────
# 1. INPUT GUARD
# ─────────────────────────────────────────────
def check_input(
    user_input: str,
    confidence_threshold: float | None = None,
) -> GuardResult:
    """
    Analiza el input del usuario y devuelve un GuardResult.

    El análisis se hace en orden de severidad. El primer patrón que supere
    el umbral bloquea la petición sin evaluar el resto (fast-fail).

    Aplica normalización de texto antes del análisis para resistir:
      - Bypass por espaciado: "i g n o r a"
      - Bypass por homoglifos unicode: "Сomo" (cirílico)
      - Bypass por leet speak: "1gnor4"

    Args:
        user_input: Texto introducido por el usuario.
        confidence_threshold: Umbral mínimo para bloquear (default: SECURITY_CONFIDENCE_THRESHOLD del .env).

    Returns:
        GuardResult con blocked=True si se detecta una amenaza.
    """
    if confidence_threshold is None:
        confidence_threshold = float(os.getenv("SECURITY_CONFIDENCE_THRESHOLD", "0.6"))

    text = user_input.strip()

    # Casos triviales
    if not text:
        return GuardResult(blocked=False)

    # Fix #4: Límite de longitud antes de cualquier análisis
    if len(text) > MAX_INPUT_LENGTH:
        return GuardResult(
            blocked=True,
            threat_type="input_too_long",
            confidence=1.0,
            safe_response=_SAFE_RESPONSES["input_too_long"],
        )

    # Fix #1 + #7: Normalizar el texto para resistir bypass
    normalized_text = _normalize(text)

    checks = [
        ("jailbreak",           _JAILBREAK_PATTERNS),
        ("prompt_injection",    _PROMPT_INJECTION_PATTERNS),
        ("system_prompt_leak",  _SYSTEM_PROMPT_LEAK_PATTERNS),
        ("off_topic",           _OFF_TOPIC_SEVERE_PATTERNS),
    ]

    for threat_type, patterns in checks:
        confidence = _score_patterns(normalized_text, patterns)
        if confidence >= confidence_threshold:
            return GuardResult(
                blocked=True,
                threat_type=threat_type,
                confidence=round(confidence, 3),
                safe_response=_SAFE_RESPONSES[threat_type],
            )

    return GuardResult(blocked=False, confidence=0.0)


# ─────────────────────────────────────────────
# 2. OUTPUT GUARD
# ─────────────────────────────────────────────
def filter_output(response: str) -> GuardResult:
    """
    Analiza la respuesta generada por el LLM antes de mostrarla al usuario.
    Detecta si el LLM filtró información del system prompt o instrucciones internas.

    Args:
        response: Texto generado por el LLM.

    Returns:
        GuardResult con blocked=True si la respuesta debe ser reemplazada.
    """
    confidence = _score_patterns(response, _OUTPUT_LEAK_PATTERNS)
    if confidence >= 0.80:   # umbral más alto para output (menos falsos positivos)
        return GuardResult(
            blocked=True,
            threat_type="output_leak",
            confidence=round(confidence, 3),
            safe_response=_SAFE_RESPONSES["output_leak"],
        )
    return GuardResult(blocked=False)


# ─────────────────────────────────────────────
# 3. RATE LIMITER
# ─────────────────────────────────────────────
# Almacén en memoria como fallback rápido: {session_id: [timestamp1, timestamp2, ...]}
_rate_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def check_rate_limit(session_id: str, max_per_minute: int | None = None) -> GuardResult:
    """
    Comprueba si el session_id ha superado el límite de mensajes por minuto.

    Usa rate limiting en SQLite (persistente entre reinicios) como capa primaria.
    La caché en memoria actúa como fast-path para no consultar la BD en cada mensaje.

    Args:
        session_id: Identificador único de la sesión de Streamlit.
        max_per_minute: Máximo de mensajes permitidos por minuto.
                        Default: RATE_LIMIT_PER_MINUTE del .env (o 15 si no está definido).

    Returns:
        GuardResult con blocked=True si se ha superado el límite.
    """
    if max_per_minute is None:
        max_per_minute = int(os.getenv("RATE_LIMIT_PER_MINUTE", "15"))

    now = time.time()
    window = 60.0  # segundos

    # ── Fast-path: caché en memoria ──────────────────
    with _rate_lock:
        timestamps = _rate_store.get(session_id, [])
        timestamps = [t for t in timestamps if now - t < window]
        timestamps.append(now)
        _rate_store[session_id] = timestamps
        in_memory_count = len(timestamps)

    # Si el contador en memoria ya supera el límite, bloqueamos sin ir a la BD
    if in_memory_count > max_per_minute:
        return GuardResult(
            blocked=True,
            threat_type="rate_limit",
            confidence=1.0,
            safe_response=_SAFE_RESPONSES["rate_limit"],
        )

    # ── Capa persistente: SQLite ──────────────────────
    # Importamos aquí para evitar importación circular (database importa security en algunos flujos)
    try:
        import database as db
        db.record_rate_event(session_id)
        count_db = db.count_recent_messages(session_id, int(window))
        if count_db > max_per_minute:
            return GuardResult(
                blocked=True,
                threat_type="rate_limit",
                confidence=1.0,
                safe_response=_SAFE_RESPONSES["rate_limit"],
            )
    except Exception:
        # Si la BD falla, nos apoyamos solo en la caché en memoria
        pass

    return GuardResult(blocked=False)
