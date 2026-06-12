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
"""

import os
import re
import time
import threading
from dataclasses import dataclass, field


# ─────────────────────────────────────────────
# Resultado del análisis de seguridad
# ─────────────────────────────────────────────
@dataclass
class GuardResult:
    blocked: bool
    threat_type: str | None = None   # "jailbreak" | "prompt_injection" | "system_prompt_leak" | "off_topic" | "output_leak" | None
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
}


# ─────────────────────────────────────────────
# Patrones de detección de amenazas (INPUT)
# ─────────────────────────────────────────────

# Cada entrada: (patrón_regex, peso_de_confianza)
_JAILBREAK_PATTERNS: list[tuple[str, float]] = [
    # Instrucciones directas de evasión
    (r"ignora\s+(las\s+)?instrucciones", 0.95),
    (r"olvida\s+(todo|las instrucciones|lo anterior)", 0.95),
    (r"ignore\s+(previous|all|your)\s+instructions", 0.95),
    (r"forget\s+(everything|your instructions)", 0.90),
    (r"bypass\s+(your\s+)?(instructions|rules|restrictions)", 0.95),
    (r"jailbreak", 0.98),
    (r"\bDAN\b", 0.85),                               # "Do Anything Now"
    (r"do\s+anything\s+now", 0.90),
    # Cambio de rol
    (r"actúa\s+como\s+(si\s+fueras\s+)?(un\s+)?(?!asistente de ventas)", 0.80),
    (r"pretend\s+(you\s+are|to\s+be)", 0.80),
    (r"role.?play", 0.75),
    (r"act\s+as\s+(if\s+you\s+are\s+)?(?!a\s+(retail|sales))", 0.80),
    (r"eres\s+ahora\s+un\s+", 0.85),
    (r"a\s+partir\s+de\s+ahora\s+(eres|serás|actúa)", 0.90),
    # Frases de escape clásicas
    (r"(new|nuevo)\s+(prompt|instrucción|instruction)", 0.85),
    (r"override\s+(your\s+)?(system|instructions|rules)", 0.90),
    (r"modo\s+(desarrollador|developer|sin\s+restricciones)", 0.90),
]

_PROMPT_INJECTION_PATTERNS: list[tuple[str, float]] = [
    # Intentos de inyectar texto de sistema
    (r"system\s*:", 0.85),
    (r"<\s*system\s*>", 0.90),
    (r"<\s*instructions?\s*>", 0.90),
    (r"\[INST\]", 0.85),
    (r"###\s*(system|instruction|context)", 0.80),
    (r'""".*"""', 0.70),                              # triple comillas con contenido
    (r"\n\n(Human|Assistant|User)\s*:", 0.85),         # simulación de turno de conversación
    (r"<\|im_start\|>", 0.95),                        # tokens de ChatML
    (r"BEGINNING OF CONVERSATION", 0.85),
]

_SYSTEM_PROMPT_LEAK_PATTERNS: list[tuple[str, float]] = [
    (r"(cuál|qué|cual|que)\s+es\s+tu\s+(prompt|instrucción|system prompt)", 0.90),
    (r"(muéstrame|dime|revela)\s+(tu\s+)?(prompt|instrucciones internas|system)", 0.90),
    (r"what\s+(are\s+your\s+)?(system\s+)?(prompt|instructions)", 0.90),
    (r"show\s+(me\s+)?(your\s+)?(prompt|instructions|system)", 0.85),
    (r"repeat\s+(your\s+)?(system|initial)\s+(prompt|instructions)", 0.90),
    (r"print\s+(your\s+)?(system\s+)?prompt", 0.85),
    (r"(texto|contenido)\s+(del\s+)?(prompt|instrucción)\s+(del\s+)?(sistema)", 0.85),
]

_OFF_TOPIC_SEVERE_PATTERNS: list[tuple[str, float]] = [
    # Peticiones de código
    (r"(escribe|genera|crea|write|generate)\s+(un\s+)?(código|código fuente|script|programa|code)", 0.80),
    (r"(haz|make)\s+(un\s+)?(exploit|malware|virus|hack)", 0.98),
    # Contenido inapropiado
    (r"(contenido|content)\s+(para\s+adultos|adult|sexual|pornográfico)", 0.98),
    (r"(drogas|drugs|narcóticos|armas|weapons|explosivos)", 0.85),
    # Petición de datos personales ajenos
    (r"(datos personales|información personal)\s+(de\s+)?(otros|clientes|usuarios)", 0.90),
]


def _score_patterns(text: str, patterns: list[tuple[str, float]]) -> float:
    """
    Evalúa el texto contra una lista de patrones regex con peso.
    Devuelve la confianza máxima encontrada (0.0 si ningún patrón coincide).
    """
    text_lower = text.lower()
    max_confidence = 0.0
    for pattern, weight in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
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
    (r"mi\s+(prompt|instrucción)\s+(es|dice|indica)", 0.85),
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

    checks = [
        ("jailbreak",           _JAILBREAK_PATTERNS),
        ("prompt_injection",    _PROMPT_INJECTION_PATTERNS),
        ("system_prompt_leak",  _SYSTEM_PROMPT_LEAK_PATTERNS),
        ("off_topic",           _OFF_TOPIC_SEVERE_PATTERNS),
    ]

    for threat_type, patterns in checks:
        confidence = _score_patterns(text, patterns)
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
# Almacén en memoria: {session_id: [timestamp1, timestamp2, ...]}
_rate_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def check_rate_limit(session_id: str, max_per_minute: int | None = None) -> GuardResult:
    """
    Comprueba si el session_id ha superado el límite de mensajes por minuto.

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

    with _rate_lock:
        timestamps = _rate_store.get(session_id, [])
        # Eliminar timestamps fuera de la ventana de 1 minuto
        timestamps = [t for t in timestamps if now - t < window]
        timestamps.append(now)
        _rate_store[session_id] = timestamps

        if len(timestamps) > max_per_minute:
            return GuardResult(
                blocked=True,
                threat_type="rate_limit",
                confidence=1.0,
                safe_response=_SAFE_RESPONSES["rate_limit"],
            )

    return GuardResult(blocked=False)
