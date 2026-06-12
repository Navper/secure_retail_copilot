"""
app.py — Secure Retail AI Copilot (Chat Interface)

Interfaz de chat principal con pipeline de seguridad multicapa:
  [1] Rate limiter   → limita mensajes por sesión/minuto
  [2] Input Guard    → detecta jailbreaks, inyecciones, off-topic ANTES del LLM
  [3] RAG Chain      → genera la respuesta si el input es seguro
  [4] Output Guard   → filtra respuestas con posible fuga del system prompt
  [5] Logger         → persiste todas las interacciones en SQLite
"""

import os
import time
import streamlit as st
from dotenv import load_dotenv

import database as db
import rag_pipeline as rag
import security

# ─────────────────────────────────────────────
# Cargar variables de entorno
# ─────────────────────────────────────────────
load_dotenv()

# ─────────────────────────────────────────────
# Configuración de página
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Secure Retail AI Copilot",
    page_icon="🛍️",
    layout="centered",
)

# ─────────────────────────────────────────────
# Inicializar base de datos
# ─────────────────────────────────────────────
db.init_db()

# ─────────────────────────────────────────────
# Session ID único para rate limiting
# ─────────────────────────────────────────────
if "session_id" not in st.session_state:
    import uuid
    st.session_state.session_id = str(uuid.uuid4())

SESSION_ID = st.session_state.session_id

# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 Configuración")

    env_key = os.getenv("GOOGLE_API_KEY", "")
    if env_key:
        st.success("✅ API Key cargada desde `.env`")
    else:
        api_key_input = st.text_input("Google Gemini API Key", type="password",
                                      placeholder="Introduce tu clave aquí...")
        if api_key_input:
            os.environ["GOOGLE_API_KEY"] = api_key_input

    st.divider()

    df_stats = db.get_all_products()
    st.markdown("### 📊 Catálogo")
    st.metric("Productos", len(df_stats))
    st.metric("Stock total", int(df_stats["stock"].sum()))
    st.metric("Valor inventario",
              f"{(df_stats['price'] * df_stats['stock']).sum():,.2f} €")

    st.divider()
    st.markdown("### 🛡️ Seguridad (esta sesión)")
    blocked_count = st.session_state.get("blocked_count", 0)
    st.metric("Intentos bloqueados", blocked_count,
              delta="⚠️ Actividad sospechosa" if blocked_count >= 3 else None,
              delta_color="inverse")

    st.divider()
    st.markdown("### 💬 Conversación")
    if st.button("🗑️ Limpiar historial", use_container_width=True):
        st.session_state.messages = []
        st.rerun()


# ─────────────────────────────────────────────
# Verificar API Key
# ─────────────────────────────────────────────
if not os.getenv("GOOGLE_API_KEY"):
    st.info("👈 Por favor, introduce tu Google Gemini API Key en la barra lateral para continuar.")
    st.stop()


# ─────────────────────────────────────────────
# Configurar el pipeline RAG
# ─────────────────────────────────────────────
# El vectorstore se cachea por hash del catálogo; el chain se reconstruye
# en cada carga (solo objetos Python, sin llamadas a la API).
def setup_pipeline():
    df = db.get_all_products()
    df_hash = hash(df.to_json())
    vectorstore = rag.get_cached_vectorstore(df_hash, df)
    retriever = vectorstore.as_retriever(search_kwargs={"k": 4})
    chain = rag.get_rag_chain(retriever)
    return chain


try:
    chain = setup_pipeline()
except Exception as e:
    st.error(f"❌ Error al configurar el sistema. Comprueba tu API Key. Detalle: {e}")
    st.stop()


# ─────────────────────────────────────────────
# Interfaz de chat
# ─────────────────────────────────────────────
st.title("🛍️ Secure Retail AI Copilot")
st.markdown(
    "Bienvenido a **Secure Retail**. Pregúntame sobre nuestros productos, "
    "disponibilidad de stock o pide una recomendación."
)

if "messages" not in st.session_state:
    st.session_state.messages = []
if "blocked_count" not in st.session_state:
    st.session_state.blocked_count = 0

# Mostrar historial
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ─────────────────────────────────────────────
# Procesamiento de nuevo mensaje
# ─────────────────────────────────────────────
if user_input := st.chat_input("¿Qué estás buscando hoy?"):

    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    t0 = time.time()
    response: str
    guard_result = None

    with st.chat_message("assistant"):
        # ── [1] Rate limiting ──────────────────────
        rate_result = security.check_rate_limit(SESSION_ID)
        if rate_result.blocked:
            response = rate_result.safe_response
            guard_result = rate_result
            st.warning(response)

        else:
            # ── [2] Input Guard ────────────────────
            input_result = security.check_input(user_input)

            if input_result.blocked:
                response = input_result.safe_response
                guard_result = input_result
                st.session_state.blocked_count += 1
                st.warning(f"🛡️ {response}")

            else:
                # ── [3] RAG Chain ──────────────────
                with st.spinner("Buscando en el catálogo..."):
                    try:
                        history_for_llm = st.session_state.messages[:-1]
                        raw_response = rag.invoke_chain(chain, user_input, history_for_llm)

                        # ── [4] Output Guard ───────
                        output_result = security.filter_output(raw_response)
                        if output_result.blocked:
                            response = output_result.safe_response
                            guard_result = output_result
                            st.session_state.blocked_count += 1
                            st.warning(f"🛡️ {response}")
                        else:
                            response = raw_response
                            st.markdown(response)

                    except Exception as e:
                        response = f"❌ Se produjo un error: {e}"
                        st.error(response)

    # ── [5] Logging ────────────────────────────────
    latency_ms = int((time.time() - t0) * 1000)
    db.log_interaction(
        session_id=SESSION_ID,
        user_input=user_input,
        response=response if not (guard_result and guard_result.blocked) else None,
        blocked=guard_result.blocked if guard_result else False,
        threat_type=guard_result.threat_type if guard_result else None,
        confidence=guard_result.confidence if guard_result else None,
        latency_ms=latency_ms,
    )

    st.session_state.messages.append({"role": "assistant", "content": response})
