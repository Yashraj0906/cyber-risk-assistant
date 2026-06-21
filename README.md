# TawasolPay — AI-Powered Cyber Risk Assessment

**Live Demo:** [cyber-risk-assistant.streamlit.app](https://cyber-risk-assistant-nszp7eqkganw7nasvhs558.streamlit.app/)  
**Repository:** [github.com/Yashraj0906/cyber-risk-assistant](https://github.com/Yashraj0906/cyber-risk-assistant)

An AI-powered system that ingests TawasolPay's cybersecurity data, scores vulnerabilities using multi-factor risk analysis (not just CVSS), retrieves relevant NIST SP 800-53 controls via a hybrid RAG pipeline, and generates actionable remediation guidance using an LLM.

---

## Architecture

```mermaid
graph TD
    subgraph Data Ingestion
        A1[assets.csv<br/>60 assets] --> DP[Data Processor]
        A2[vulnerabilities.csv<br/>114 vulns] --> DP
        A3[threat_intelligence.csv<br/>40 records] --> DP
        A4[business_services.csv<br/>20 services] --> DP
        A5[remediation_guidance.csv] --> DP
        A6[synthetic_threat_report.md] --> DP
        A7[CISA KEV API<br/>cisa.gov] --> DP
    end

    subgraph Risk Scoring
        DP --> |Enriched DataFrame<br/>114 rows x 41 cols| RS[Risk Scorer<br/>10 weighted factors]
        RS --> |Top 5 risks<br/>with score breakdowns| TOP5[Top 5 Risks]
    end

    subgraph RAG Pipeline
        NIST[NIST SP 800-53 Rev 5<br/>1,016 controls from OSCAL JSON] --> CH[Chunker<br/>control-aware chunking]
        CH --> |1,016 chunks| EMB[BGE Embeddings<br/>bge-small-en-v1.5]
        CH --> |1,016 chunks| BM[BM25 Index<br/>keyword search]
        EMB --> VDB[(ChromaDB<br/>vector store)]

        TOP5 --> QA[Query Augmentation<br/>risk context → rich query]
        QA --> VDB
        QA --> BM
        VDB --> |top 10 dense| RRF[Reciprocal Rank Fusion]
        BM --> |top 10 sparse| RRF
        RRF --> |top 10 fused| RE[Cross-Encoder Reranker<br/>ms-marco-MiniLM-L-6-v2]
        RE --> |top 3 controls| CTRL[Retrieved NIST Controls]
    end

    subgraph LLM Generation
        TOP5 --> LLM[Llama 3.3 70B<br/>via Groq API]
        CTRL --> LLM
        LLM --> OUT[Risk Explanation +<br/>Remediation Guidance]
    end

    subgraph Web Interface
        OUT --> ST[Streamlit App]
        TOP5 --> ST
        CTRL --> ST
    end
```

---

## How It Works

### 1. Data Ingestion (`src/data_loader.py`, `src/data_processor.py`)

Loads 6 local files + 2 external sources and joins them into a single enriched DataFrame:

```
vulnerabilities.csv (114 rows)
  + assets.csv (on asset_id) → asset_type, environment, internet_exposed, edr_installed
  + business_services.csv (on business_service) → revenue_impact, compliance_scope, rto_hours
  + threat_intelligence.csv (on CVE) → threat_actor, campaign_name, ransomware_association
  + CISA KEV catalog (on CVE) → kev_confirmed, kev_ransomware
= Enriched DataFrame (114 rows × 41 columns)
```

External data is cached locally after first download to avoid repeated API calls.

### 2. Multi-Factor Risk Scoring (`src/risk_scorer.py`)

Each vulnerability is scored using 10 weighted factors. CVSS is intentionally de-weighted (only 0-5 points out of ~100) because a CVSS-10 on an internal dev server is less dangerous than a CVSS-8 on an internet-facing VPN with active ransomware campaigns.

| Factor | Points | Source |
|--------|--------|--------|
| Internet-exposed asset | 25 | assets.csv |
| Exploit available/weaponized | 20 | vulnerabilities.csv + threat_intel |
| CISA KEV confirmed | 15 | CISA KEV API |
| Ransomware associated | 15 | threat_intel + KEV |
| Critical business service | 10 | business_services.csv |
| Compliance scope | 5 | business_services.csv |
| No EDR installed | 5 | assets.csv |
| Production environment | 3 | assets.csv |
| CVSS normalized | 0-5 | vulnerabilities.csv |
| Customer-facing | 2 | business_services.csv |

### 3. Hybrid RAG Pipeline (`src/rag_pipeline.py`)

For each of the top 5 risks, the pipeline retrieves the 3 most relevant NIST controls:

```mermaid
graph LR
    Q[Risk Context] --> QA[Query Augmentation]
    QA --> D[Dense Search<br/>BGE embeddings + ChromaDB]
    QA --> S[Sparse Search<br/>BM25 keywords]
    D --> |top 10| RRF[Reciprocal Rank Fusion]
    S --> |top 10| RRF
    RRF --> |top 10 fused| CR[Cross-Encoder Reranking<br/>ms-marco-MiniLM-L-6-v2]
    CR --> |top 3| R[Final Controls]
```

**Why hybrid?** Dense search (embeddings) catches semantic meaning ("patching" ↔ "flaw remediation"). Sparse search (BM25) catches exact terms ("AC-17" ↔ "AC-17"). RRF combines both rank lists without score scale issues. The cross-encoder then re-scores each (query, document) pair with full cross-attention for precise final ranking.

### 4. LLM Generation (`src/output_generator.py`, `src/llm_client.py`)

Each risk + its retrieved NIST controls are sent to Llama 3.3 70B (via Groq) with a system prompt that enforces:
- Explain WHY this risk is ranked at this position (grounded in the scoring data)
- For each NIST control, provide actionable remediation steps
- Use ONLY the provided context (no hallucination from training data)

### 5. Evaluation (`src/rag_evaluator.py`)

The retrieval pipeline is evaluated on a golden test set (5 queries with expected NIST controls):

| Metric | Score | Meaning |
|--------|-------|---------|
| Hit Rate @3 | 1.0 | The primary expected control appears in top 3 for all queries |
| MRR | 0.9 | Average reciprocal rank of the primary control |
| Context Precision | 1.0 | All retrieved controls are from the expected set |

A faithfulness checker also verifies that NIST control IDs mentioned in LLM output were actually retrieved (catches hallucinated controls).

---

## Project Structure

```
cyber-risk-assistant/
├── app.py                      # Streamlit web interface
├── requirements.txt            # Python dependencies
├── .env.example                # API key template
├── src/
│   ├── data_loader.py          # Load CSVs + fetch CISA KEV & NIST OSCAL
│   ├── data_processor.py       # Join all sources into enriched DataFrame
│   ├── risk_scorer.py          # 10-factor weighted risk scoring
│   ├── chunker.py              # NIST controls → embedding-ready chunks
│   ├── embeddings.py           # BGE-small-en-v1.5 embedding model
│   ├── vector_store.py         # ChromaDB persistent vector store
│   ├── sparse_retriever.py     # BM25 keyword-based retrieval
│   ├── rag_pipeline.py         # Full RAG orchestrator (hybrid + rerank)
│   ├── llm_client.py           # Groq API client (Llama 3.3 70B)
│   ├── output_generator.py     # LLM prompt engineering for explanations
│   └── rag_evaluator.py        # Hit Rate, MRR, Context Precision evaluation
├── data/
│   ├── assets.csv              # 60 assets (VPN gateways, servers, etc.)
│   ├── vulnerabilities.csv     # 114 vulnerabilities with CVE, CVSS, severity
│   ├── threat_intelligence.csv # 40 threat actor records
│   ├── business_services.csv   # 20 business services with revenue impact
│   ├── remediation_guidance.csv
│   └── synthetic_threat_report.md
├── eval/
│   ├── golden_set.json         # 5 test queries with expected NIST controls
│   └── eval_results.json       # Evaluation metrics output
├── tests/
│   └── test_pipeline.py        # 12 automated tests (data, scoring, RAG)
└── chroma_db/                  # Persistent vector store (auto-generated)
```

---

## Run Locally

```bash
# clone
git clone https://github.com/Yashraj0906/cyber-risk-assistant.git
cd cyber-risk-assistant

# setup
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt

# add your Groq API key
cp .env.example .env
# edit .env and add: GROQ_API_KEY=your_key_here

# run
streamlit run app.py

# tests
python -m pytest tests/ -v
```

---

## Tech Stack

| Component | Tool | Why |
|-----------|------|-----|
| LLM | Llama 3.3 70B via Groq | Free tier, fast inference, no cold starts |
| Embeddings | BAAI/bge-small-en-v1.5 | Instruction-prefixed queries improve retrieval accuracy |
| Reranker | cross-encoder/ms-marco-MiniLM-L-6-v2 | Full cross-attention scoring for precise top-3 selection |
| Sparse Search | BM25 (rank-bm25) | Catches exact keyword matches embeddings miss |
| Vector Store | ChromaDB | Persistent, local, no external service needed |
| Fusion | Reciprocal Rank Fusion | Combines rank lists without score scale issues |
| Web UI | Streamlit | Fast prototyping, built-in deployment |

---

## Supporting Question 1 — The Data Split

**I embedded the NIST SP 800-53 controls** (1,016 documents). These are written in natural language — paragraphs describing what each security control does and how to implement it. To find the right control for a given vulnerability, I need semantic search (e.g., a query about "patching a VPN" should match a control called "Flaw Remediation" even though the words are different).

**I queried the CSVs as structured records** using pandas joins and filters. Assets, vulnerabilities, threat intel, and business services all have clear columns like `asset_id`, `cve`, `business_service` that connect them. A SQL-style join is the right way to combine these — embedding a CSV row into a vector would throw away the column-level meaning.

## Supporting Question 2 — Where It Goes Wrong

1. **A new zero-day won't get flagged if CISA hasn't added it to KEV yet.** My system checks the CISA KEV catalog to decide if a CVE is actively exploited. If a vulnerability is being exploited in the wild but CISA hasn't listed it yet, the system misses 15 points of risk score. I'd fix this by also checking EPSS (Exploit Prediction Scoring System) which gives a probability of exploitation without needing a manual catalog entry.

2. **Only one threat actor is kept per CVE.** When merging threat intelligence, I deduplicate by CVE and keep the highest-confidence match. So if CVE-2024-21762 is used by both a ransomware group and a nation-state APT, the system only sees one of them. I'd fix this by aggregating — take the worst-case signal from all threat actors linked to that CVE.

3. **The retriever sometimes pulls the right NIST family but wrong sub-control.** For example, searching for "VPN authentication bypass" might return IA-2(13) "Out-of-band Authentication" instead of the more relevant IA-2(1) "Multi-Factor Authentication." The cross-encoder reranker helps, but doesn't fully solve it. I'd fix this by filtering controls by asset type before reranking (e.g., only show network-related controls for network devices).

## Supporting Question 3 — One Thing I Would Change

I would **learn the scoring weights from real breach data instead of setting them by hand.** Right now the weights are hardcoded (internet exposure = 25 pts, exploit = 20 pts, etc.) based on what security teams generally consider important. This works, but it's based on my judgment, not evidence. With another day, I'd train a simple XGBoost model on historical incident data where the label is "was this vulnerability actually exploited in a real breach?" — that way the model learns which factors actually predict real-world attacks, rather than relying on manual assumptions.

---

## Evaluation Results

```
12 tests passed (pytest)
Hit Rate @3:        1.0
MRR:                0.9
Context Precision:  1.0
```
