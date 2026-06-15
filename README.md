# Secure Retail AI Copilot

## Tabla de Contenidos
- [Descripción del Proyecto](#descripción-del-proyecto)
- [Arquitectura del Sistema](#arquitectura-del-sistema)
- [Stack Tecnológico](#stack-tecnológico)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Instrucciones de Despliegue](#instrucciones-de-despliegue)
- [Funcionalidades Implementadas](#funcionalidades-implementadas)
- [Seguridad](#seguridad)
- [Configuración Adicional](#configuración-adicional)

---

## Descripción del Proyecto

**Secure Retail AI Copilot** es un asistente de ventas conversacional impulsado por Inteligencia Artificial, diseñado para una tienda de mobiliario y accesorios de oficina. La aplicación permite a los usuarios consultar el catálogo de productos, comprobar disponibilidad de stock y recibir recomendaciones personalizadas a través de una interfaz de chat natural.

El proyecto está construido sobre un pipeline **RAG (Retrieval-Augmented Generation)** con memoria conversacional, respaldado por una capa de seguridad multicapa que protege la aplicación frente a jailbreaks, prompt injection, y abuso de la API.

---

## Arquitectura del Sistema

El sistema opera bajo un flujo de procesamiento en cinco capas secuenciales:

1. **Rate Limiter**: Controla el número de mensajes por sesión por minuto. Implementado con doble capa: caché en memoria (fast-path) + persistencia en SQLite (sobrevive reinicios).
2. **Input Guard**: Analiza el input del usuario antes de que llegue al LLM. Detecta jailbreaks, prompt injection, intentos de extracción del system prompt y contenido fuera de tema mediante regex con normalización de texto (unicode, leet speak, espaciado).
3. **RAG Chain**: Recupera los productos más relevantes del catálogo mediante búsqueda semántica (FAISS) y genera una respuesta contextual con historial de conversación usando Gemini.
4. **Output Guard**: Filtra la respuesta del LLM antes de mostrarla, bloqueando cualquier fuga de información del system prompt.
5. **Logger**: Persiste todas las interacciones (bloqueadas y no bloqueadas) en SQLite con métricas de seguridad para el panel de administración.

---

## Stack Tecnológico

### Backend y Lógica de Negocio
- **Python 3.10+**
- **LangChain** — Orquestación del pipeline RAG con memoria conversacional
- **Google Generative AI API** (Gemini 2.5 Flash) — LLM para generación y embeddings
- **FAISS** — Vector store local para búsqueda semántica de productos
- **SQLite** — Base de datos local para catálogo, logs de seguridad y rate limiting
- **Pandas** — Manipulación y estructuración de datos

### Frontend y UI
- **Streamlit** — Framework de aplicación web con páginas múltiples
- **Python-dotenv** — Gestión segura de variables de entorno

### Seguridad
- **hashlib + hmac** — Hash SHA256 con timing-safe comparison para autenticación de admin
- **unicodedata + regex** — Normalización de texto para resistir bypass con homoglifos y leet speak

### Resumen de Tecnologías

| Componente | Tecnologías | Uso Principal |
|---|---|---|
| UI & Chat | Streamlit | Interfaz de chat y paneles de administración |
| RAG Pipeline | LangChain + FAISS | Recuperación semántica + generación con contexto |
| LLM & Embeddings | Google Gemini API | NLP, generación de respuestas y vectorización |
| Base de datos | SQLite + Pandas | Catálogo, logs de seguridad y rate limiting |
| Seguridad Input | unicodedata + regex | Detección de jailbreaks y normalización de texto |
| Autenticación Admin | hashlib + hmac | Hash de contraseñas timing-safe |

---

## Estructura del Proyecto

```
secure_retail_copilot/
├── app.py                  # Aplicación principal — interfaz de chat con pipeline de seguridad
├── rag_pipeline.py         # Pipeline RAG con memoria conversacional (LangChain + FAISS)
├── security.py             # Capa de seguridad multicapa (InputGuard, OutputGuard, RateLimiter)
├── database.py             # Capa de acceso a datos SQLite (productos, logs, rate limit)
├── auth.py                 # Módulo de autenticación SHA256 + hmac para panel de admin
├── inventory.csv           # Datos iniciales del catálogo (migrados a SQLite en el primer arranque)
├── requirements.txt        # Dependencias del proyecto
├── .env.example            # Plantilla de variables de entorno (sin valores reales)
├── .gitignore              # Excluye .env, venv, retail.db y __pycache__
└── pages/
    ├── admin.py            # Panel de administración CRUD del catálogo con reindexado RAG
    └── security_logs.py    # Panel de logs de seguridad con KPIs, gráficos y exportación CSV
```

---

## Instrucciones de Despliegue

### Prerrequisitos
- Python 3.10 o superior
- Una clave de API de Google Gemini ([obtener aquí](https://aistudio.google.com/app/apikey))

### Instalación

**1. Clonar el repositorio:**
```bash
git clone https://github.com/Navper/secure_retail_copilot.git
cd secure_retail_copilot
```

**2. Crear y activar el entorno virtual:**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Instalar dependencias:**
```bash
pip install -r requirements.txt
```

**4. Configurar variables de entorno:**
```bash
# Copiar la plantilla
copy .env.example .env   # Windows
cp .env.example .env     # macOS/Linux

# Editar .env y añadir tu GOOGLE_API_KEY
```

**5. (Recomendado) Configurar contraseña de admin con hash:**
```bash
python -c "from auth import hash_password; print(hash_password('tu_password_segura'))"
# Pega el resultado en .env como: ADMIN_PASSWORD_HASH=<hash>
```

**6. Lanzar la aplicación:**
```bash
streamlit run app.py
```

---

## Funcionalidades Implementadas

### Chat Principal (`app.py`)
- Interfaz de chat conversacional con historial de sesión (hasta 10 turnos)
- Pipeline de seguridad de 5 capas visible en tiempo real
- Métricas de seguridad en sidebar (intentos bloqueados por sesión)
- API Key cargada desde `.env` o introducida manualmente en la UI

### Panel de Administración (`pages/admin.py`)
- Autenticación con contraseña hasheada (SHA256 + hmac)
- Edición inline del catálogo completo de productos
- Formulario validado para añadir nuevos productos con ID autogenerado
- Eliminación de productos con confirmación
- Reindexado manual del vector store RAG sin reiniciar la app

### Panel de Seguridad (`pages/security_logs.py`)
- KPIs en tiempo real: total de queries, tasa de bloqueo, amenaza más frecuente, latencia media
- Tabla de logs filtrable por tipo de amenaza y estado (bloqueado/permitido)
- Gráfico de distribución de amenazas detectadas
- Exportación de logs a CSV

---

## Seguridad

La aplicación implementa una arquitectura de defensa en profundidad (**defense-in-depth**):

| Capa | Mecanismo | Protege contra |
|---|---|---|
| Rate Limiter | Ventana deslizante en SQLite + RAM | Abuso de API, DoS por coste |
| Input Guard | Regex con normalización unicode/leet | Jailbreaks, prompt injection, off-topic |
| Límite de longitud | Max 2000 caracteres por mensaje | DoS por coste de tokens |
| Output Guard | Regex sobre respuesta del LLM | Fugas del system prompt |
| Logger | SQLite con flags de amenaza | Auditoría y detección de patrones |
| Auth Admin | SHA256 + `hmac.compare_digest()` | Timing attacks en autenticación |

> **Nota**: La defensa por regex proporciona una primera capa rápida y explicable. Para producción a escala, se recomienda complementar con un clasificador semántico como [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) o [Llama Guard](https://ai.meta.com/research/publications/llama-guard-safeguarding-llms-with-human-in-the-loop/).

---

## Configuración Adicional

### Variables de entorno (`.env`)

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `GOOGLE_API_KEY` | Clave de API de Google Gemini | *(obligatoria)* |
| `ADMIN_PASSWORD_HASH` | Hash SHA256 de la contraseña de admin | *(vacío → usa ADMIN_PASSWORD)* |
| `ADMIN_PASSWORD` | Contraseña admin en texto plano (fallback) | `admin123` |
| `PASSWORD_SALT` | Salt para el hashing de contraseñas | `secure_retail_default_salt_v1` |
| `RATE_LIMIT_PER_MINUTE` | Máximo de mensajes por sesión por minuto | `15` |
| `SECURITY_CONFIDENCE_THRESHOLD` | Umbral de confianza para bloquear inputs (0.0–1.0) | `0.6` |
| `MAX_INPUT_LENGTH` | Longitud máxima del input en caracteres | `2000` |

### Base de Datos

La aplicación crea automáticamente `retail.db` (SQLite) en el directorio raíz en el primer arranque, migrando los datos de `inventory.csv`. El archivo está excluido del repositorio vía `.gitignore`.
