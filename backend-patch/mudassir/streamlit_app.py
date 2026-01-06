import os
import json
import streamlit as st
from typing import Dict, Any
from dotenv import load_dotenv

# Import the pipeline from main.py
from main import run_pipeline


st.set_page_config(page_title="Secure Patch Generator", layout="wide")
st.title("Secure Patch Generator (RAG + Groq)")
st.caption("Retrieve → Generate → Verify → Persist using ChromaDB and Qwen via Groq")

# Ensure environment variables from .env are loaded
load_dotenv()

with st.sidebar:
    st.header("Settings")
    chroma_path = os.path.join(os.getcwd(), "chroma")
    st.write(f"Chroma Path: {chroma_path}")
    top_k = st.slider("Top-K retrieval", min_value=1, max_value=10, value=3)
    model_name = st.text_input("Groq Model Name", value=os.getenv("GROQ_MODEL", "qwen/qwen3-32b"))
    api_key_default = os.getenv("GROQ_API_KEY", "")
    api_key_input = st.text_input("Groq API Key (overrides .env)", value=api_key_default, type="password")
    if api_key_input:
        os.environ["GROQ_API_KEY"] = api_key_input

st.subheader("Structured Input")
col1, col2 = st.columns(2)
with col1:
    language = st.text_input("Language", value="C++")
    vulnerability_type = st.text_input("Vulnerability Type", value="Buffer Overflow")
with col2:
    context = st.text_area("Context", value="Function readInput() handles user input without bounds checking.", height=100)

vulnerable_code = st.text_area("Vulnerable Code", value="char buf[10]; gets(buf);", height=160)

run_btn = st.button("Run Pipeline")

def to_structured() -> Dict[str, Any]:
    return {
        "language": language,
        "vulnerability_type": vulnerability_type,
        "vulnerable_code": vulnerable_code,
        "context": context,
    }

if run_btn:
    with st.spinner("Running pipeline..."):
        try:
            result = run_pipeline(to_structured(), chroma_path=chroma_path, model_name=model_name, top_k=top_k)
        except Exception as e:
            st.error(f"Error: {e}")
            st.stop()

    st.success("Pipeline finished")

    st.subheader("Summary")
    colA, colB, colC = st.columns(3)
    colA.metric("Strategy", result.get("strategy"))
    colB.metric("Top similarity", f"{result.get('similarity', 0.0):.3f}")
    colC.metric("Accepted", str(result.get("accepted")))

    st.subheader("Validation")
    val = result.get("validation", {})
    st.write(val)
    if val.get("compile_output"):
        with st.expander("Compiler Output"):
            st.text(val.get("compile_output"))

    st.subheader("Patch")
    patch_code = result.get("patch_code", "")
    # Try to map language to streamlit code language
    lang = "cpp" if "++" in (language or "").lower() or "cpp" in (language or "").lower() else "c"
    st.code(patch_code, language=lang)

    st.subheader("Explanation")
    st.write(result.get("explanation", ""))

    st.subheader("Retrieved Examples")
    for i, ex in enumerate(result.get("retrieved_examples", []), start=1):
        with st.expander(f"Example {i} | CVE: {ex.get('cve_id','')} | CWE: {ex.get('cwe_id','')} | Severity: {ex.get('severity','')}"):
            st.markdown("**Description**")
            st.write(ex.get("description", ""))
            st.markdown("**Vulnerable**")
            st.code(ex.get("vulnerable_code", ""), language=lang)
            st.markdown("**Patch**")
            st.code(ex.get("patch_code", ""), language=lang)
            st.markdown("**Root Cause**")
            st.write(ex.get("root_cause", ""))

st.markdown("---")
st.caption("Set GROQ_API_KEY in environment or .env at repo root, or provide it in the sidebar.")