"""
pages/admin.py — Panel de Administración de Catálogo para Secure Retail AI Copilot.

Funcionalidades:
  - Ver y editar el catálogo completo de productos (inline con st.data_editor)
  - Añadir nuevos productos con formulario validado
  - Eliminar productos con confirmación
  - Reindexar el vector store RAG manualmente
"""

import os
import sys

import streamlit as st
from dotenv import load_dotenv

# Añadir el directorio raíz al path para poder importar database y rag_pipeline
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Cargar variables de entorno (.env) — necesario porque cada página
# de Streamlit se ejecuta de forma independiente.
load_dotenv()

import database as db
import rag_pipeline as rag
import auth

# ─────────────────────────────────────────────
# Configuración de página
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Admin — Secure Retail",
    page_icon="⚙️",
    layout="wide",
)

# ─────────────────────────────────────────────
# Autenticación simple con contraseña
# ─────────────────────────────────────────────
# Fix #3: La contraseña se verifica via auth.py con SHA256 + hmac.compare_digest()
# Ver auth.py para instrucciones de cómo configurar ADMIN_PASSWORD_HASH en .env

if "admin_authenticated" not in st.session_state:
    st.session_state.admin_authenticated = False

if not st.session_state.admin_authenticated:
    st.title("⚙️ Panel de Administración")
    st.markdown("Acceso restringido. Introduce la contraseña de administrador.")

    with st.form("login_form"):
        password = st.text_input("Contraseña", type="password")
        submitted = st.form_submit_button("Acceder")

    if submitted:
        if auth.verify_admin_password(password):
            st.session_state.admin_authenticated = True
            st.rerun()
        else:
            st.error("❌ Contraseña incorrecta.")
    st.stop()

# ─────────────────────────────────────────────
# Panel principal (solo si está autenticado)
# ─────────────────────────────────────────────
db.init_db()

st.title("⚙️ Panel de Administración — Catálogo")
st.markdown("Gestiona el inventario de productos de **Secure Retail**.")

# Botón de logout en sidebar
with st.sidebar:
    st.markdown("### ⚙️ Administración")
    if st.button("🚪 Cerrar sesión"):
        st.session_state.admin_authenticated = False
        st.rerun()

    st.divider()
    df_sidebar = db.get_all_products()
    st.metric("Productos totales", len(df_sidebar))
    st.metric("Unidades en stock", int(df_sidebar["stock"].sum()))
    st.metric("Valor del inventario",
              f"{(df_sidebar['price'] * df_sidebar['stock']).sum():,.2f} €")

# ═══════════════════════════════════════════
# Sección 1: Tabla de edición inline
# ═══════════════════════════════════════════
st.subheader("📦 Inventario actual")

df = db.get_all_products()

CATEGORIES = ["General", "Mobiliario", "Accesorios", "Electrónica",
              "Iluminación", "Papelería", "Seguridad", "Acústica"]

edited_df = st.data_editor(
    df,
    use_container_width=True,
    num_rows="fixed",
    column_config={
        "id": st.column_config.TextColumn("ID", disabled=True, width="small"),
        "name": st.column_config.TextColumn("Nombre", width="large"),
        "description": st.column_config.TextColumn("Descripción", width="large"),
        "price": st.column_config.NumberColumn("Precio (€)", min_value=0.0, format="%.2f"),
        "stock": st.column_config.NumberColumn("Stock", min_value=0, step=1),
        "category": st.column_config.SelectboxColumn("Categoría", options=CATEGORIES),
    },
    hide_index=True,
    key="product_editor",
)

col_save, col_reindex = st.columns([1, 1])

with col_save:
    if st.button("💾 Guardar cambios en el catálogo", type="primary", use_container_width=True):
        changes = 0
        for _, row in edited_df.iterrows():
            updated = db.update_product(
                product_id=row["id"],
                name=row["name"],
                description=row["description"],
                price=float(row["price"]),
                stock=int(row["stock"]),
                category=row["category"],
            )
            if updated:
                changes += 1
        st.success(f"✅ {changes} productos actualizados correctamente.")
        st.info("ℹ️ Recuerda reindexar el catálogo para que el chat refleje los cambios.")

with col_reindex:
    if st.button("🔄 Reindexar catálogo (RAG)", use_container_width=True):
        with st.spinner("Generando embeddings y reconstruyendo el índice FAISS..."):
            try:
                fresh_df = db.get_all_products()
                # ✅ Limpiamos SOLO la caché del vectorstore, no la caché global.
                # Esto evita destruir el chain RAG de app.py innecesariamente.
                rag.get_cached_vectorstore.clear()
                df_hash = hash(fresh_df.to_json())
                rag.get_cached_vectorstore(df_hash, fresh_df)
                st.success("✅ Catálogo reindexado correctamente. El chat usará los datos actualizados.")
            except Exception as e:
                st.error(f"❌ Error al reindexar: {e}")

st.divider()

# ═══════════════════════════════════════════
# Sección 2: Añadir nuevo producto
# ═══════════════════════════════════════════
st.subheader("➕ Añadir nuevo producto")

with st.form("add_product_form", clear_on_submit=True):
    col1, col2 = st.columns(2)

    with col1:
        new_name = st.text_input("Nombre del producto *")
        new_price = st.number_input("Precio (€) *", min_value=0.0, step=0.01, format="%.2f")
        new_category = st.selectbox("Categoría", options=CATEGORIES)

    with col2:
        new_stock = st.number_input("Unidades en stock *", min_value=0, step=1)
        new_id_auto = db.get_next_product_id()
        st.text_input("ID (autogenerado)", value=new_id_auto, disabled=True)

    new_description = st.text_area("Descripción *", height=100,
                                   placeholder="Descripción detallada del producto...")

    submitted = st.form_submit_button("➕ Añadir producto", type="primary")

    if submitted:
        errors = []
        if not new_name.strip():
            errors.append("El nombre no puede estar vacío.")
        if not new_description.strip():
            errors.append("La descripción no puede estar vacía.")
        if new_price <= 0:
            errors.append("El precio debe ser mayor que 0.")

        if errors:
            for err in errors:
                st.error(f"❌ {err}")
        else:
            try:
                db.add_product(
                    product_id=new_id_auto,
                    name=new_name.strip(),
                    description=new_description.strip(),
                    price=float(new_price),
                    stock=int(new_stock),
                    category=new_category,
                )
                st.success(f"✅ Producto **{new_name}** ({new_id_auto}) añadido correctamente.")
                st.info("ℹ️ Recuerda reindexar el catálogo para que aparezca en el chat.")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error al añadir el producto: {e}")

st.divider()

# ═══════════════════════════════════════════
# Sección 3: Eliminar producto
# ═══════════════════════════════════════════
st.subheader("🗑️ Eliminar producto")

df_for_delete = db.get_all_products()
product_options = {
    f"{row['id']} — {row['name']}": row["id"]
    for _, row in df_for_delete.iterrows()
}

selected_label = st.selectbox(
    "Selecciona el producto a eliminar",
    options=list(product_options.keys()),
    index=None,
    placeholder="Elige un producto...",
)

if selected_label:
    selected_id = product_options[selected_label]
    st.warning(f"⚠️ Vas a eliminar: **{selected_label}**. Esta acción no se puede deshacer.")

    if st.button("🗑️ Confirmar eliminación", type="primary"):
        deleted = db.delete_product(selected_id)
        if deleted:
            st.success(f"✅ Producto **{selected_label}** eliminado.")
            st.info("ℹ️ Recuerda reindexar el catálogo.")
            st.rerun()
        else:
            st.error(f"❌ No se pudo eliminar el producto {selected_id}.")
