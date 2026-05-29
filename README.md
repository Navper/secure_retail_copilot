# Secure Retail AI Copilot

## Project Overview
The Secure Retail AI Copilot is a proof-of-concept (PoC) conversational agent designed for a fictional retail store, "Secure Retail". This application allows users to consult a product catalog, check stock, and receive recommendations through an intuitive chat interface. It leverages a Retrieval-Augmented Generation (RAG) pipeline to query a local vector database of products and uses strict system prompting to ensure safe and focused interactions.

## Architecture
The application is built using a modern AI stack:
- **Frontend**: [Streamlit](https://streamlit.io/) provides a clean, responsive chat interface.
- **Orchestration**: [LangChain](https://python.langchain.com/) manages the RAG pipeline, chaining together the retriever, prompt template, and LLM.
- **Language Model & Embeddings**: [OpenAI API](https://openai.com/) (GPT-3.5-Turbo and text-embedding-ada-002) is used for natural language generation and text embedding.
- **Vector Database**: [FAISS](https://github.com/facebookresearch/faiss) (Facebook AI Similarity Search) is used as an efficient, local vector store for fast similarity search.
- **Data Handling**: [Pandas](https://pandas.pydata.org/) is used to manage and process the product inventory data.

## Security & Risk Mitigation
Security is a critical component of this PoC. AI assistants are vulnerable to prompt injection, jailbreaks, and data leakage. 

### Current PoC Defenses
In this PoC, security is enforced via **Strict System Prompting** (Guardrails via Prompting). The LLM is explicitly instructed to:
1. Act exclusively as a retail assistant for "Secure Retail".
2. Never reveal its internal system instructions or context.
3. Refuse any requests to write code, generate unrelated content, or discuss off-topic subjects.
4. Base its answers *only* on the provided retrieved context.

### Scaling Security for Production
While system prompting provides a baseline defense, a production-grade application requires a more robust, multi-layered security architecture:
1. **Input/Output Validation (Guardrails):** Implement specialized frameworks like [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) or [Llama Guard](https://ai.meta.com/research/publications/llama-guard-safeguarding-llms-with-human-in-the-loop/) to semantically route and block malicious inputs before they reach the core LLM, and to filter outputs.
2. **Content Safety API:** Integrate services like [Azure AI Content Safety](https://azure.microsoft.com/en-us/products/ai-services/ai-content-safety) to detect and block toxicity, hate speech, and jailbreak attempts at the API level.
3. **Data Privacy (PII Scrubbing):** Use tools like Microsoft Presidio to detect and anonymize Personally Identifiable Information (PII) before logging or processing queries.
4. **Rate Limiting & Authentication:** Prevent denial-of-wallet attacks and abuse by implementing strict rate limiting and requiring user authentication.

## Setup Instructions

### Prerequisites
- Python 3.10 or higher
- An OpenAI API Key

### Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd secure_retail_copilot
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the Application:**
   ```bash
   streamlit run app.py
   ```

6. **Usage:**
   - Upon launching, the application will automatically generate a sample `inventory.csv` if one does not exist.
   - Enter your OpenAI API Key in the sidebar.
   - Start chatting with the Secure Retail assistant!
