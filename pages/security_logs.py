"""
pages/security_logs.py — Panel de Logs de Seguridad para Secure Retail AI Copilot.

Muestra en tiempo real:
  - KPIs: total queries, % bloqueadas, amenaza más frecuente, latencia media.
  - Tabla de logs filtrable (tipo de amenaza, solo bloqueadas, etc.)
  - Gráfico de distribución de amenazas.
  - Exportación a CSV.
"""

import os
import sys
import io

import streamlit as st
import pandas as pd
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
load_dotenv()

import database as db

# ─────────────────────────────────────────────
# Configuración de página
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Security Logs — Secure Retail",
    page_icon="🔐",
    layout="wide",
)

# ─────────────────────────────────────────────
# Autenticación (misma contraseña que admin)
# ─────────────────────────────────────────────
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

if "sec_authenticated" not in st.session_state:
    st.session_state.sec_authenticated = False

if not st.session_state.sec_authenticated:
    st.title("🔐 Logs de Seguridad")
    st.markdown("Acceso restringido.")
    with st.form("sec_login"):
        pwd = st.text_input("Contraseña de administrador", type="password")
        if st.form_submit_button("Acceder"):
            if pwd == ADMIN_PASSWORD:
                st.session_state.sec_authenticated = True
                st.rerun()
            else:
                st.error("❌ Contraseña incorrecta.")
    st.stop()

# ─────────────────────────────────────────────
# Inicializar BD (crea tabla si es nueva instancia)
# ─────────────────────────────────────────────
db.init_db()

# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔐 Seguridad")
    if st.button("🚪 Cerrar sesión"):
        st.session_state.sec_authenticated = False
        st.rerun()

    st.divider()

    # Filtros
    st.markdown("### 🔎 Filtros")
    only_flagged = st.toggle("Solo interacciones bloqueadas", value=False)

    threat_options = ["Todas", "jailbreak", "prompt_injection",
                      "system_prompt_leak", "off_topic", "output_leak", "rate_limit"]
    selected_threat = st.selectbox("Tipo de amenaza", options=threat_options)
    threat_filter = None if selected_threat == "Todas" else selected_threat

    log_limit = st.slider("Nº de registros a mostrar", min_value=10,
                          max_value=500, value=100, step=10)

    st.divider()
    if st.button("🗑️ Limpiar todos los logs", type="primary", use_container_width=True):
        n = db.clear_logs()
        st.success(f"✅ {n} registros eliminados.")
        st.rerun()

# ─────────────────────────────────────────────
# Contenido principal
# ─────────────────────────────────────────────
st.title("🔐 Panel de Seguridad — Logs de Conversación")

# ── KPIs ──────────────────────────────────────
stats = db.get_security_stats()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total de queries", stats["total"])
col2.metric(
    "Bloqueadas",
    stats["blocked"],
    delta=f"{stats['block_rate']}% del total",
    delta_color="inverse" if stats["block_rate"] > 0 else "off",
)
col3.metric(
    "Amenaza más frecuente",
    max(stats["threat_breakdown"], key=stats["threat_breakdown"].get)
    if stats["threat_breakdown"] else "—",
)
col4.metric("Latencia media", f"{stats['avg_latency_ms']} ms")

st.divider()

# ── Gráfico de distribución de amenazas ──────
if stats["threat_breakdown"]:
    st.subheader("📊 Distribución de amenazas detectadas")
    threat_df = pd.DataFrame(
        list(stats["threat_breakdown"].items()),
        columns=["Tipo de amenaza", "Ocurrencias"],
    ).sort_values("Ocurrencias", ascending=False)
    st.bar_chart(threat_df.set_index("Tipo de amenaza"))
    st.divider()

# ── Tabla de logs ──────────────────────────────
st.subheader("📋 Registro de interacciones")

logs_df = db.get_logs(limit=log_limit, only_flagged=only_flagged,
                      threat_filter=threat_filter)

if logs_df.empty:
    st.info("No hay logs que coincidan con los filtros seleccionados.")
else:
    # Colorear filas bloqueadas
    def highlight_blocked(row):
        if row["blocked"] == 1:
            return ["background-color: #3d1c1c"] * len(row)
        return [""] * len(row)

    # Renombrar columnas para mejor legibilidad
    display_df = logs_df.rename(columns={
        "id": "ID",
        "session_id": "Sesión",
        "timestamp": "Timestamp (UTC)",
        "user_input": "Input usuario",
        "response": "Respuesta",
        "blocked": "Bloqueado",
        "threat_type": "Tipo amenaza",
        "confidence": "Confianza",
        "latency_ms": "Latencia (ms)",
    })

    # Truncar textos largos para la tabla
    display_df["Input usuario"] = display_df["Input usuario"].str[:120] + "…"
    display_df["Respuesta"] = display_df["Respuesta"].fillna("—").str[:80] + "…"
    display_df["Bloqueado"] = display_df["Bloqueado"].map({1: "🔴 SÍ", 0: "🟢 NO"})

    st.dataframe(
        display_df.style.apply(highlight_blocked, axis=1),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Confianza": st.column_config.ProgressColumn(
                "Confianza", min_value=0.0, max_value=1.0, format="%.2f"
            ),
            "Latencia (ms)": st.column_config.NumberColumn("Latencia (ms)"),
        },
    )

    st.caption(f"Mostrando {len(logs_df)} de los últimos registros.")

    # ── Exportar CSV ──────────────────────────────
    st.subheader("📥 Exportar")
    csv_buffer = io.StringIO()
    logs_df.to_csv(csv_buffer, index=False)
    st.download_button(
        label="⬇️ Descargar logs como CSV",
        data=csv_buffer.getvalue(),
        file_name="secure_retail_security_logs.csv",
        mime="text/csv",
        use_container_width=True,
    )
