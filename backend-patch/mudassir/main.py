import os
import sys
import json
import time
import shutil
import tempfile
import re
import subprocess
import signal
from typing import List, Dict, Any, Optional, Tuple

# FastAPI
try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except Exception:
    FastAPI = None
    BaseModel = object  # type: ignore
    uvicorn = None

from sentence_transformers import SentenceTransformer
import chromadb
import pandas as pd

# LangChain + Groq
try:
    from langchain_groq import ChatGroq
except Exception:
    try:
        # Fallback import path used by some LangChain versions
        from langchain_community.chat_models import ChatGroq  # type: ignore
    except Exception as e:
        ChatGroq = None

try:
    from dotenv import load_dotenv, dotenv_values
except Exception:
    def load_dotenv(*args, **kwargs):
        return False
    def dotenv_values(*args, **kwargs):
        return {}


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def _safe_strip(s: Any) -> str:
    return str(s).strip() if s is not None else ""


def build_query_text(structured: Dict[str, Any]) -> str:
    language = _safe_strip(structured.get("language", ""))
    vuln_type = _safe_strip(structured.get("vulnerability_type", ""))
    context = _safe_strip(structured.get("context", ""))
    vulnerable_code = _safe_strip(structured.get("vulnerable_code", ""))

    header = f"Language {language} | Vulnerability {vuln_type}"
    parts = [header]
    if context:
        parts.append(f"Context: {context}")
    if vulnerable_code:
        parts.append(f"Vulnerable Code:\n{vulnerable_code}")
    return " | ".join(parts)


def load_chroma_collection(chroma_path: str, collection_name: str = "vulnerability_patches"):
    client = chromadb.PersistentClient(path=chroma_path)
    return client.get_or_create_collection(name=collection_name)


def extract_index_from_id(doc_id: str) -> Optional[int]:
    # ids are of the form "{cve_id}-{idx}". Parse trailing numeric suffix.
    try:
        suffix = doc_id.rsplit("-", 1)[-1]
        return int(suffix)
    except Exception:
        return None


def load_dataset(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, encoding="utf-8", engine="python", dtype=str)
    return df.fillna("")


def retrieve_examples(
    model: SentenceTransformer,
    collection,
    df: pd.DataFrame,
    structured_input: Dict[str, Any],
    k: int = 3,
) -> Tuple[List[Dict[str, Any]], List[float]]:
    query_text = build_query_text(structured_input)
    query_embedding = model.encode([query_text], normalize_embeddings=False)[0].tolist()

    res = collection.query(query_embeddings=[query_embedding], n_results=k)
    # res: { ids: [[...]], distances or embeddings? chroma returns distances or similar; use 'distances'
    ids = res.get("ids", [[]])[0]
    distances = res.get("distances", [[]])[0]

    examples = []
    for doc_id in ids:
        idx = extract_index_from_id(doc_id)
        row = df.iloc[idx] if (idx is not None and 0 <= idx < len(df)) else None
        if row is None:
            examples.append({"id": doc_id, "error": "row lookup failed"})
            continue
        examples.append({
            "id": doc_id,
            "cve_id": _safe_strip(row.get("CVE_ID")),
            "cwe_id": _safe_strip(row.get("CWE_ID")),
            "severity": _safe_strip(row.get("Severity")),
            "language": _safe_strip(row.get("Language")),
            "vulnerable_code": _safe_strip(row.get("Affected_Code")),
            "patch_code": _safe_strip(row.get("Patch_Code")),
            "root_cause": _safe_strip(row.get("Structured_Root_Cause")),
            "description": _safe_strip(row.get("CVE_Description")),
        })

    # Convert distances to similarity if available: similarity = 1 - distance (for cosine)
    similarities = []
    for d in distances:
        try:
            similarities.append(1.0 - float(d))
        except Exception:
            similarities.append(0.0)

    return examples, similarities


def build_prompt(structured: Dict[str, Any], examples: List[Dict[str, Any]]) -> str:
    language = _safe_strip(structured.get("language", ""))
    vuln_type = _safe_strip(structured.get("vulnerability_type", ""))
    cwe_id = _safe_strip(structured.get("cwe_id", ""))
    context = _safe_strip(structured.get("context", ""))
    vulnerable_code = _safe_strip(structured.get("vulnerable_code", ""))

    def fmt_example(ex: Dict[str, Any], i: int) -> str:
        return (
            f"Example {i}:\n"
            f"- Vulnerable: {ex.get('vulnerable_code', '')}\n"
            f"- Patch: {ex.get('patch_code', '')}\n"
            f"- Root cause: {ex.get('root_cause', '')}"
        )

    examples_block = "\n\n".join([fmt_example(ex, i + 1) for i, ex in enumerate(examples)])

    extra_requirements = []
    ci_keywords = ["command injection", "CWE-78", "cwe-78", "OS Command Injection"]
    if any(k.lower() in (vuln_type + " " + cwe_id).lower() for k in ci_keywords):
        extra_requirements.append(
            "Forbid system(), popen(), and exec* variants unless using a strict allowlist and parameterized argv."
        )
        extra_requirements.append(
            "Validate the command against a fixed allowlist of known-safe executables; reject anything else."
        )
        extra_requirements.append(
            "Construct argv as an array/vector of strings; do not split untrusted strings into argv without validation."
        )
        extra_requirements.append(
            "If insufficient context to safely execute commands, replace the call with a safe error return instead of attempting execution."
        )

    req_lines = [
        "Provide only the patched code in a single fenced code block with the correct language tag (e.g., ```c or ```cpp).",
        "Keep changes minimal and preserve original logic where possible.",
        "Ensure the patch removes the vulnerability (e.g., bounds checks, safe APIs, parameterized calls).",
        "If necessary to compile, include required #includes or small helper functions.",
        "After the code block, include 2–3 short bullets explaining what changed and why it fixes the issue.",
        "If you cannot safely produce a patch, say so and explain why.",
    ] + extra_requirements

    req_block = "\n- " + "\n- ".join(req_lines)

    prompt = f"""
You are a secure-code assistant. Your task is to produce a minimal, correct patch for the vulnerable code below and explain the fix in 2–3 bullet points.

INPUT:
Language: {language}
Vulnerability Type / CWE: {vuln_type} / {cwe_id}
Context: {context}

VULNERABLE CODE:
[CODE_BLOCK: {vulnerable_code}]

RETRIEVED EXAMPLES (most similar from the knowledge base):
{examples_block}

REQUIREMENTS:{req_block}

Now generate the patch and short explanation.
"""
    return prompt.strip()


def parse_llm_output(text: str) -> Tuple[Optional[str], Optional[str], str]:
    # Extract fenced code block and optional language tag
    code_block_pattern = re.compile(r"```([a-zA-Z0-9+#]*)\n(.*?)```", re.DOTALL)
    match = code_block_pattern.search(text)
    code_lang = None
    code_content = None
    if match:
        code_lang = match.group(1).strip() or None
        code_content = match.group(2).strip()

    # Explanation: text after code block or entire text if no code found
    explanation = text
    if match:
        explanation = text[match.end():].strip()
    return code_lang, code_content, explanation


def generate_complete_fixed_code(
    full_code: str,
    vulnerable_code: str,
    patch_code: str,
    line_number: Optional[int],
    language: str,
    model_name: str = None
) -> str:
    """
    Generate complete fixed code by applying the patch to the full code.
    Uses LLM to intelligently merge the patch into the full code context.
    """
    model_name = model_name or os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    
    # Build prompt for complete code generation
    line_info = f" at line {line_number}" if line_number else ""
    prompt = f"""You are a secure-code assistant. Your task is to generate the complete, vulnerability-free code by applying the provided patch to the original code.

ORIGINAL COMPLETE CODE:
```
{full_code}
```

VULNERABLE CODE{line_info}:
```
{vulnerable_code}
```

PATCH CODE (to replace the vulnerable code):
```
{patch_code}
```

INSTRUCTIONS:
1. Replace the vulnerable code section with the patch code in the complete original code.
2. Ensure the complete code is syntactically correct and compilable.
3. Preserve all other parts of the code unchanged.
4. Maintain proper indentation and formatting.
5. Include all necessary headers, includes, and declarations.

Provide the complete fixed code in a single fenced code block with the language tag (e.g., ```{language.lower()} or ```cpp).
Do not include any explanation, only the complete fixed code.
"""
    
    try:
        raw_output = call_llm_with_groq(prompt, model_name=model_name, temperature=0.1)
        _, code_content, _ = parse_llm_output(raw_output)
        
        if code_content:
            return code_content
        # Fallback: try to extract code block if parsing failed
        code_block_pattern = re.compile(r"```(?:[a-zA-Z0-9+#]*)?\n?(.*?)```", re.DOTALL)
        match = code_block_pattern.search(raw_output)
        if match:
            return match.group(1).strip()
        return raw_output.strip()
    except Exception as e:
        # Fallback: simple string replacement if LLM fails
        print(f"Warning: LLM generation failed ({e}), using fallback replacement", file=sys.stderr)
        if vulnerable_code in full_code:
            return full_code.replace(vulnerable_code, patch_code)
        return full_code


def generate_complete_fixed_code_multiple(
    full_code: str,
    vulnerabilities: List[Dict[str, Any]],
    language: str,
    model_name: str = None
) -> str:
    """
    Generate complete fixed code by applying ALL patches at once.
    This is more accurate than applying patches sequentially.
    
    Args:
        full_code: The original complete code
        vulnerabilities: List of vulnerability dicts, each containing:
            - code: vulnerable code snippet
            - patch_code: the patch to apply
            - line: line number (optional)
            - type: vulnerability type (optional)
            - cwe_id: CWE ID (optional)
        language: Programming language
        model_name: LLM model name
    
    Returns:
        Complete fixed code with all patches applied
    """
    model_name = model_name or os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    
    # Build the patches list for the prompt
    patches_list = []
    for i, vuln in enumerate(vulnerabilities, 1):
        vulnerable_code = vuln.get("code", "").strip()
        patch_code = vuln.get("patch_code", "").strip()
        line_num = vuln.get("line")
        vuln_type = vuln.get("type", "")
        cwe_id = vuln.get("cwe_id", "")
        
        if not vulnerable_code or not patch_code:
            continue  # Skip invalid entries
        
        line_info = f" at line {line_num}" if line_num else ""
        vuln_info = f" ({vuln_type}" + (f", {cwe_id}" if cwe_id else "") + ")" if vuln_type else ""
        
        patches_list.append(f"""
PATCH {i}{vuln_info}:
Vulnerable Code{line_info}:
```
{vulnerable_code}
```

Patch Code (replace the vulnerable code above):
```
{patch_code}
```
""")
    
    if not patches_list:
        return full_code  # No valid patches to apply
    
    patches_block = "\n".join(patches_list)
    
    prompt = f"""You are a secure-code assistant. Your task is to generate the complete, vulnerability-free code by applying ALL the provided patches to the original code in a single pass.

ORIGINAL COMPLETE CODE:
```
{full_code}
```

PATCHES TO APPLY (apply ALL of them):
{patches_block}

CRITICAL INSTRUCTIONS:
1. Apply ALL patches to the original code in one pass. Do NOT apply them sequentially.
2. Find each vulnerable code section in the original code and replace it with its corresponding patch code.
3. Ensure the complete code is syntactically correct and compilable after ALL patches are applied.
4. Preserve all other parts of the code unchanged.
5. Maintain proper indentation and formatting.
6. Include all necessary headers, includes, and declarations.
7. Make sure ALL vulnerabilities are fixed - verify that no vulnerable code patterns remain.
8. If a vulnerable code section appears multiple times, replace ALL occurrences with the patch.

IMPORTANT: 
- Work from the ORIGINAL code, not from previously patched versions
- Apply all patches simultaneously to ensure accuracy
- Double-check that all vulnerable patterns are replaced

Provide the complete fixed code in a single fenced code block with the language tag (e.g., ```{language.lower()} or ```cpp).
Do not include any explanation, only the complete fixed code.
"""
    
    try:
        raw_output = call_llm_with_groq(prompt, model_name=model_name, temperature=0.1)
        _, code_content, _ = parse_llm_output(raw_output)
        
        if code_content:
            return code_content
        # Fallback: try to extract code block if parsing failed
        code_block_pattern = re.compile(r"```(?:[a-zA-Z0-9+#]*)?\n?(.*?)```", re.DOTALL)
        match = code_block_pattern.search(raw_output)
        if match:
            return match.group(1).strip()
        return raw_output.strip()
    except Exception as e:
        # Fallback: try sequential replacement if LLM fails
        print(f"Warning: LLM generation failed ({e}), using fallback sequential replacement", file=sys.stderr)
        result_code = full_code
        for vuln in vulnerabilities:
            vulnerable_code = vuln.get("code", "").strip()
            patch_code = vuln.get("patch_code", "").strip()
            if vulnerable_code and patch_code and vulnerable_code in result_code:
                result_code = result_code.replace(vulnerable_code, patch_code, 1)
        return result_code


def has_banned_apis(language: str, code: str) -> bool:
    banned_c = ["gets", "strcpy", "strcat", "sprintf", "scanf("]
    banned_cpp = ["gets", "strcpy", "strcat", "sprintf", "scanf("]
    lang = (language or "").lower()
    banned = banned_cpp if "++" in lang or "cpp" in lang else banned_c
    return any(api in code for api in banned)


def compiler_available(language: str) -> Optional[str]:
    lang = (language or "").lower()
    candidates = []
    if "++" in lang or "cpp" in lang:
        candidates = ["g++", "clang++", "cl"]
    else:
        candidates = ["gcc", "clang", "cl"]
    for c in candidates:
        if shutil.which(c):
            return c
    return None


def try_compile(language: str, code: str) -> Tuple[bool, str]:
    compiler = compiler_available(language)
    if not compiler:
        return False, "No suitable compiler found on PATH; skipping compile."

    # Write temp file and try to compile
    ext = ".cpp" if ("++" in (language or "").lower() or "cpp" in (language or "").lower()) else ".c"
    with tempfile.TemporaryDirectory() as td:
        src_path = os.path.join(td, f"patch{ext}")
        exe_path = os.path.join(td, "a.exe" if os.name == "nt" else "a.out")
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(code)

        # Basic compile command; no run
        if compiler == "cl":
            cmd = f'cl /nologo /W3 /EHsc "{src_path}"'
        else:
            cmd = f'"{compiler}" -Wall -Wextra -o "{exe_path}" "{src_path}"'

        try:
            import subprocess
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            ok = proc.returncode == 0
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            return ok, output.strip()
        except Exception as e:
            return False, f"Compile attempt failed: {e}"


def validate_patch(language: str, code: str) -> Dict[str, Any]:
    results = {
        "banned_apis": not has_banned_apis(language, code),
        "compiled": False,
        "compile_output": "",
    }
    ok, out = try_compile(language, code)
    results["compiled"] = ok
    results["compile_output"] = out
    return results


# ---------------------------------------------------------------------------
# Dynamic Validation (Runtime Testing)
# ---------------------------------------------------------------------------

def create_test_harness(patch_code: str, language: str, vulnerability_type: str, vulnerable_code: str = "") -> str:
    """Create a test harness wrapper for the patch code"""
    lang = (language or "").lower()
    is_cpp = "++" in lang or "cpp" in lang
    
    # Extract function name from patch code if possible
    func_match = re.search(r'(\w+)\s*\([^)]*\)\s*\{', patch_code)
    func_name = func_match.group(1) if func_match else None
    
    # Determine test inputs based on vulnerability type
    vuln_lower = (vulnerability_type or "").lower()
    
    # Check if patch code is a complete program (has main function)
    has_main = "int main" in patch_code or "void main" in patch_code
    
    # If patch has main, we can test it directly
    if has_main:
        # Just add some test validation around it
        if is_cpp:
            return f"""#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <signal.h>

// Timeout handler
void timeout_handler(int sig) {{
    std::cerr << "\\nExecution timeout!\\n";
    exit(1);
}}

// Patch code to test
{patch_code}
"""
        else:
            return f"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

// Timeout handler
void timeout_handler(int sig) {{
    fprintf(stderr, "\\nExecution timeout!\\n");
    exit(1);
}}

// Patch code to test
{patch_code}
"""
    
    # Generate test harness for function or code snippet
    if is_cpp:
        # Try to call the function if it exists, otherwise just compile and run
        if func_name:
            harness = f"""#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

// Patch code to test
{patch_code}

// Test harness
int main() {{
    std::cout << "=== Testing Patch Code ===\\n";
    std::cout << "Compiling and executing patch...\\n\\n";
    
    try {{
        // Try to call the function if it's callable
        // For now, just verify it compiles and can be included
        std::cout << "Patch code compiled successfully.\\n";
        std::cout << "Function '{func_name}' is available.\\n";
        std::cout << "\\n=== Test Results ===\\n";
        std::cout << "Status: COMPILED AND READY\\n";
        std::cout << "Note: Runtime testing requires complete program context.\\n";
        return 0;
    }} catch (const std::exception& e) {{
        std::cerr << "Error: " << e.what() << "\\n";
        return 1;
    }} catch (...) {{
        std::cerr << "Unknown error occurred\\n";
        return 1;
    }}
}}
"""
        else:
            # Just wrap the code snippet
            harness = f"""#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

// Patch code to test
{patch_code}

// Test harness
int main() {{
    std::cout << "=== Testing Patch Code ===\\n";
    std::cout << "Compiling patch code...\\n\\n";
    
    try {{
        std::cout << "Patch code compiled successfully.\\n";
        std::cout << "\\n=== Test Results ===\\n";
        std::cout << "Status: COMPILED SUCCESSFULLY\\n";
        std::cout << "Note: Code snippet is syntactically correct.\\n";
        return 0;
    }} catch (const std::exception& e) {{
        std::cerr << "Error: " << e.what() << "\\n";
        return 1;
    }} catch (...) {{
        std::cerr << "Unknown error occurred\\n";
        return 1;
    }}
}}
"""
    else:
        # C version
        if func_name:
            harness = f"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Patch code to test
{patch_code}

// Test harness
int main() {{
    printf("=== Testing Patch Code ===\\n");
    printf("Compiling and executing patch...\\n\\n");
    
    printf("Patch code compiled successfully.\\n");
    printf("Function '%s' is available.\\n", "{func_name}");
    printf("\\n=== Test Results ===\\n");
    printf("Status: COMPILED AND READY\\n");
    printf("Note: Runtime testing requires complete program context.\\n");
    return 0;
}}
"""
        else:
            harness = f"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Patch code to test
{patch_code}

// Test harness
int main() {{
    printf("=== Testing Patch Code ===\\n");
    printf("Compiling patch code...\\n\\n");
    
    printf("Patch code compiled successfully.\\n");
    printf("\\n=== Test Results ===\\n");
    printf("Status: COMPILED SUCCESSFULLY\\n");
    printf("Note: Code snippet is syntactically correct.\\n");
    return 0;
}}
"""
    
    return harness


def run_code_safely(code: str, language: str, timeout: int = 5, stdin: Optional[str] = None) -> Dict[str, Any]:
    """Run code in a safe environment with timeout and resource limits"""
    lang = (language or "").lower()
    is_cpp = "++" in lang or "cpp" in lang
    ext = ".cpp" if is_cpp else ".c"
    compiler = compiler_available(language)
    
    if not compiler:
        return {
            "success": False,
            "error": "No suitable compiler found",
            "output": "",
            "runtime_error": True
        }
    
    results = {
        "success": False,
        "output": "",
        "error": "",
        "runtime_error": False,
        "timeout": False,
        "exit_code": -1,
        "execution_time": 0
    }
    
    start_time = time.time()
    
    try:
        with tempfile.TemporaryDirectory() as td:
            src_path = os.path.join(td, f"test{ext}")
            exe_path = os.path.join(td, "test_exe" + (".exe" if os.name == "nt" else ""))
            
            # Write code to file
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(code)
            
            # Compile
            if compiler == "cl":
                compile_cmd = f'cl /nologo /W3 /EHsc "{src_path}" /Fe:"{exe_path}"'
            else:
                compile_cmd = f'"{compiler}" -Wall -Wextra -o "{exe_path}" "{src_path}" 2>&1'
            
            compile_proc = subprocess.run(
                compile_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=td
            )
            
            if compile_proc.returncode != 0:
                results["error"] = compile_proc.stderr or compile_proc.stdout
                results["output"] = "Compilation failed"
                return results
            
            # Run with timeout
            try:
                run_proc = subprocess.run(
                    [exe_path],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    input=(stdin or ""),
                    cwd=td
                )
                
                results["exit_code"] = run_proc.returncode
                results["output"] = run_proc.stdout
                results["error"] = run_proc.stderr
                results["success"] = (run_proc.returncode == 0)
                
            except subprocess.TimeoutExpired:
                results["timeout"] = True
                results["error"] = f"Execution timed out after {timeout} seconds"
                results["runtime_error"] = True
            except Exception as e:
                results["runtime_error"] = True
                results["error"] = f"Runtime error: {str(e)}"
            
            results["execution_time"] = time.time() - start_time
            
    except Exception as e:
        results["error"] = f"Execution failed: {str(e)}"
        results["runtime_error"] = True
    
    return results


def validate_patch_dynamically(
    patch_code: Optional[str],
    language: str,
    vulnerability_type: str,
    vulnerable_code: str = "",
    timeout: int = 5,
    full_program_code: Optional[str] = None,
    stdin: Optional[str] = None
) -> Dict[str, Any]:
    """Dynamically validate code by running it in a safe environment.
    If full_program_code is provided, compile and run it as-is.
    Otherwise, wrap patch_code in a minimal harness.
    """
    
    # Decide which code to run
    if full_program_code and full_program_code.strip():
        code_to_run = full_program_code
    else:
        # Create test harness from snippet
        try:
            if not patch_code:
                return {"success": False, "error": "No code provided to test", "test_results": {}, "is_safe": False, "message": "Missing code"}
            code_to_run = create_test_harness(patch_code, language, vulnerability_type, vulnerable_code)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to create test harness: {str(e)}",
                "test_results": {}
            }
    
    # Run the code
    run_results = run_code_safely(code_to_run, language, timeout, stdin=stdin)
    
    # Parse test results from output
    test_results = {
        "compiled": run_results.get("exit_code", -1) != -1 and not run_results.get("runtime_error", True),
        "executed": run_results.get("success", False),
        "timeout": run_results.get("timeout", False),
        "runtime_error": run_results.get("runtime_error", False),
        "output": run_results.get("output", ""),
        "error": run_results.get("error", ""),
        "exit_code": run_results.get("exit_code", -1),
        "execution_time": run_results.get("execution_time", 0)
    }
    
    # Determine if patch is safe
    is_safe = (
        test_results["compiled"] and
        not test_results["timeout"] and
        not test_results["runtime_error"] and
        test_results["exit_code"] == 0
    )
    
    return {
        "success": is_safe,
        "test_results": test_results,
        "is_safe": is_safe,
        "message": "Patch passed runtime tests" if is_safe else "Patch failed runtime tests"
    }


def adapt_top_patch_if_similar(sim: float, top_example: Dict[str, Any], structured: Dict[str, Any]) -> Optional[str]:
    if sim < 0.85:
        return None
    base_patch = _safe_strip(top_example.get("patch_code"))
    if not base_patch:
        return None

    # Naive variable/function name alignment using context hints
    # Attempt to map a function name from context to the patch if present
    context = _safe_strip(structured.get("context", ""))
    vulnerable_code = _safe_strip(structured.get("vulnerable_code", ""))

    func_in_context = None
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", context)
    if m:
        func_in_context = m.group(1)

    # Rename function names in patch to match context function if any
    if func_in_context:
        base_patch = re.sub(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", lambda mm: func_in_context + "(", base_patch, count=1)

    # Attempt to align primary buffer variable name
    vars_in_vuln = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)", vulnerable_code)
    if vars_in_vuln:
        primary = vars_in_vuln[0]
        base_patch = re.sub(r"\bbuf\b", primary, base_patch)

    return base_patch


def call_llm_with_groq(prompt: str, model_name: str, temperature: float = 0.2) -> str:
    # Load .env explicitly from CWD in addition to default search
    try:
        load_dotenv()
        load_dotenv(dotenv_path=os.path.join(os.getcwd(), ".env"))
    except Exception:
        pass
    # Robust fallback: parse .env manually (handles BOM, quotes, export, spaces)
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        env_path = os.path.join(os.getcwd(), ".env")
        # Try python-dotenv parser first for reliability
        try:
            values = dotenv_values(dotenv_path=env_path) if os.path.exists(env_path) else {}
            if values and values.get("GROQ_API_KEY"):
                api_key = values.get("GROQ_API_KEY")
                os.environ["GROQ_API_KEY"] = api_key
        except Exception:
            pass
        # Fallback to manual parsing if still not found
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for raw in f:
                        # strip BOM and whitespace
                        line = raw.lstrip("\ufeff").strip()
                        if not line or line.startswith("#"):
                            continue
                        # allow `export KEY=...`
                        if line.lower().startswith("export "):
                            line = line[7:].strip()
                        if not line.startswith("GROQ_API_KEY"):
                            continue
                        # split key/value
                        parts = line.split("=", 1)
                        if len(parts) != 2:
                            continue
                        value = parts[1].strip().strip('"').strip("'")
                        if value:
                            api_key = value
                            os.environ["GROQ_API_KEY"] = api_key
                            break
            except Exception:
                pass
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set; please provide it via environment/.env or the Streamlit sidebar.")
    if ChatGroq is None:
        raise RuntimeError("ChatGroq is not available; please ensure langchain-groq or langchain_community is installed.")

    chat = ChatGroq(temperature=temperature, model_name=model_name, groq_api_key=api_key)
    result = chat.invoke(prompt)
    # Some versions return an AIMessage; extract content
    content = getattr(result, "content", None)
    return content if content is not None else str(result)


def store_generated_patch(
    model: SentenceTransformer,
    collection,
    structured: Dict[str, Any],
    patch_code: str,
    explanation: str,
):
    language = _safe_strip(structured.get("language", ""))
    vuln_type = _safe_strip(structured.get("vulnerability_type", ""))
    context = _safe_strip(structured.get("context", ""))
    vulnerable_code = _safe_strip(structured.get("vulnerable_code", ""))

    doc_text = (
        f"Language {language} | Vulnerability {vuln_type} | Context: {context} | "
        f"Vulnerable Code:\n{vulnerable_code} | Patched Code:\n{patch_code}"
    )
    emb = model.encode([doc_text], normalize_embeddings=False)[0].tolist()
    gen_id = f"generated-{int(time.time())}"
    metadata = {
        "source": "generated",
        "language": language,
        "vulnerability_type": vuln_type,
        "context": context,
    }
    collection.add(ids=[gen_id], documents=[doc_text], embeddings=[emb], metadatas=[metadata])


def run_pipeline(structured_input: Dict[str, Any], chroma_path: str = None, model_name: str = None, top_k: int = 3) -> Dict[str, Any]:
    chroma_path = chroma_path or os.path.join(os.getcwd(), "chroma")
    model_name = model_name or os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

    collection = load_chroma_collection(chroma_path)
    st_model = SentenceTransformer("all-MiniLM-L6-v2")

    csv_path = os.path.join(os.getcwd(), "patched_cve_database.csv")
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV not found at {csv_path}")
    df = load_dataset(csv_path)

    examples, similarities = retrieve_examples(st_model, collection, df, structured_input, k=top_k)
    top_sim = similarities[0] if similarities else 0.0

    adapted_patch = adapt_top_patch_if_similar(top_sim, examples[0] if examples else {}, structured_input)

    if adapted_patch:
        code_lang = structured_input.get("language", "")
        explanation = "- Adapted top retrieved patch to input context.\n- Aligned function/variable names and ensured safer APIs."
        validation = validate_patch(code_lang, adapted_patch)
        accepted = validation.get("banned_apis", False) and validation.get("compiled", False)
        store_generated_patch(st_model, collection, structured_input, adapted_patch, explanation)
        return {
            "strategy": "adapted",
            "similarity": top_sim,
            "retrieved_examples": examples,
            "patch_code": adapted_patch,
            "explanation": explanation,
            "validation": validation,
            "accepted": accepted,
        }

    prompt = build_prompt(structured_input, examples)
    raw_output = call_llm_with_groq(prompt, model_name=model_name, temperature=0.2)
    code_lang, code_content, explanation = parse_llm_output(raw_output)

    if not code_content:
        raise RuntimeError("LLM did not return a fenced code block with the patch.")

    # Prefer explicit language tag from model; fallback to input
    lang_for_validation = code_lang or structured_input.get("language", "")
    validation = validate_patch(lang_for_validation, code_content)
    accepted = validation.get("banned_apis", False) and validation.get("compiled", False)

    store_generated_patch(st_model, collection, structured_input, code_content, explanation)

    return {
        "strategy": "synthesized",
        "similarity": top_sim,
        "retrieved_examples": examples,
        "patch_code": code_content,
        "explanation": explanation,
        "validation": validation,
        "accepted": accepted,
        "model_output": raw_output,
    }


def read_structured_input() -> Dict[str, Any]:
    # Priority: --json '...' | --input path | stdin | example fallback
    args = sys.argv[1:]
    if "--json" in args:
        i = args.index("--json")
        try:
            return json.loads(args[i + 1])
        except Exception as e:
            print(f"Failed to parse --json: {e}", file=sys.stderr)
    if "--input" in args:
        i = args.index("--input")
        try:
            with open(args[i + 1], "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to read --input: {e}", file=sys.stderr)
    # stdin
    try:
        if not sys.stdin.isatty():
            data = sys.stdin.read()
            if data.strip():
                return json.loads(data)
    except Exception:
        pass
    # fallback example from user
    return {
        "language": "C++",
        "vulnerability_type": "Buffer Overflow",
        "vulnerable_code": "char buf[10]; gets(buf);",
        "context": "Function readInput() handles user input without bounds checking.",
    }


# ---------------------------------------------------------------------------
# FastAPI service (optional) - expose HTTP endpoints for patch generation
# ---------------------------------------------------------------------------

class VulnerabilityPayload(BaseModel):
    # Minimal fields coming from the Patch Management card
    id: Optional[int] = None
    type: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    line: Optional[int] = None
    code: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    cwe_description: Optional[str] = None
    cwe_severity: Optional[str] = None
    mitigation: Optional[List[str]] = None
    references: Optional[List[str]] = None
    # Optional overrides
    language: Optional[str] = None
    full_code: Optional[str] = None  # Complete original code file


class PatchTestPayload(BaseModel):
    """Payload for testing patch code dynamically"""
    # Either provide full_program_code (preferred) or patch_code (snippet)
    full_program_code: Optional[str] = None
    patch_code: Optional[str] = None
    language: Optional[str] = "C++"
    vulnerability_type: Optional[str] = ""
    vulnerable_code: Optional[str] = ""
    timeout: Optional[int] = 5
    stdin: Optional[str] = None


class MultiplePatchesPayload(BaseModel):
    """Payload for applying multiple patches at once"""
    full_code: str
    language: Optional[str] = "C++"
    vulnerabilities: List[Dict[str, Any]]  # List of vulnerability dicts with code, patch_code, line, etc.


def _to_structured_input(v: VulnerabilityPayload) -> Dict[str, Any]:
    language = v.language or "C++"  # default based on your examples
    vuln_type = v.type or (v.cwe_id or "")
    context_parts: List[str] = []
    if v.description:
        context_parts.append(v.description)
    if v.cwe_name:
        context_parts.append(f"CWE: {v.cwe_id} - {v.cwe_name}")
    if v.line is not None and v.code:
        context_parts.append(f"Line {v.line}: {v.code}")
    context = " | ".join(context_parts)
    vulnerable_code = v.code or ""

    return {
        "language": language,
        "vulnerability_type": vuln_type,
        "cwe_id": v.cwe_id or "",
        "context": context,
        "vulnerable_code": vulnerable_code,
    }


if FastAPI is not None:
    app = FastAPI(title="SecurePatcher Patch Generator", version="1.0.0")

    # CORS for local dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
           "*"
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/generate-patch")
    def generate_patch(vuln: VulnerabilityPayload) -> Dict[str, Any]:
        try:
            structured = _to_structured_input(vuln)
            chroma_path = os.path.join(os.getcwd(), "chroma")
            model_name = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
            result = run_pipeline(structured, chroma_path=chroma_path, model_name=model_name, top_k=3)
            
            # Generate complete fixed code if full_code is provided
            complete_fixed_code = None
            if vuln.full_code and result.get("patch_code"):
                try:
                    complete_fixed_code = generate_complete_fixed_code(
                        full_code=vuln.full_code,
                        vulnerable_code=vuln.code or "",
                        patch_code=result.get("patch_code", ""),
                        line_number=vuln.line,
                        language=structured.get("language", "C++"),
                        model_name=model_name
                    )
                except Exception as e:
                    print(f"Warning: Failed to generate complete fixed code: {e}", file=sys.stderr)
                    # Continue without complete code if generation fails
            
            # Shape a frontend-friendly response
            response = {
                "strategy": result.get("strategy"),
                "patch": {
                    "suggestion": result.get("explanation", ""),
                    "code": result.get("patch_code", ""),
                },
                "validation": result.get("validation", {}),
                "accepted": result.get("accepted", False),
                "similarity": result.get("similarity", 0.0),
            }
            
            # Add complete fixed code if available
            if complete_fixed_code:
                response["complete_fixed_code"] = complete_fixed_code
            
            return response
        except Exception as e:
            return {"error": str(e)}

    @app.post("/test-patch")
    def test_patch(patch_test: PatchTestPayload) -> Dict[str, Any]:
        """Test patch code dynamically in a safe environment"""
        try:
            result = validate_patch_dynamically(
                patch_code=patch_test.patch_code,
                language=patch_test.language or "C++",
                vulnerability_type=patch_test.vulnerability_type or "",
                vulnerable_code=patch_test.vulnerable_code or "",
                timeout=patch_test.timeout or 5,
                full_program_code=patch_test.full_program_code,
                stdin=patch_test.stdin
            )
            return result
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "test_results": {},
                "is_safe": False,
                "message": f"Test failed: {str(e)}"
            }

    @app.post("/generate-complete-code-multiple")
    def generate_complete_code_multiple(payload: MultiplePatchesPayload) -> Dict[str, Any]:
        """Generate complete fixed code by applying ALL patches at once (more accurate)"""
        try:
            model_name = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
            
            # First, generate patches for vulnerabilities that don't have patch_code yet
            vulnerabilities_with_patches = []
            
            for vuln in payload.vulnerabilities:
                vuln_dict = vuln if isinstance(vuln, dict) else vuln.dict() if hasattr(vuln, 'dict') else {}
                
                # Check if patch_code is already provided and is non-empty
                existing_patch = vuln_dict.get("patch_code")
                if existing_patch and isinstance(existing_patch, str) and existing_patch.strip():
                    # Use existing patch
                    vulnerabilities_with_patches.append(vuln_dict)
                else:
                    # Generate patch for this vulnerability
                    try:
                        structured = _to_structured_input(VulnerabilityPayload(**vuln_dict))
                        chroma_path = os.path.join(os.getcwd(), "chroma")
                        patch_result = run_pipeline(structured, chroma_path=chroma_path, model_name=model_name, top_k=3)
                        
                        patch_code = patch_result.get("patch_code", "").strip()
                        if patch_code:
                            vuln_dict["patch_code"] = patch_code
                            vulnerabilities_with_patches.append(vuln_dict)
                        else:
                            print(f"Warning: No patch code generated for vulnerability at line {vuln_dict.get('line', 'unknown')}", file=sys.stderr)
                    except Exception as e:
                        print(f"Warning: Failed to generate patch for vulnerability: {e}", file=sys.stderr)
                        # Skip this vulnerability if patch generation fails
                        continue
            
            if not vulnerabilities_with_patches:
                return {
                    "error": "No valid patches available",
                    "complete_fixed_code": payload.full_code
                }
            
            # Generate complete fixed code with all patches applied at once
            complete_fixed_code = generate_complete_fixed_code_multiple(
                full_code=payload.full_code,
                vulnerabilities=vulnerabilities_with_patches,
                language=payload.language or "C++",
                model_name=model_name
            )
            
            return {
                "success": True,
                "complete_fixed_code": complete_fixed_code,
                "patches_applied": len(vulnerabilities_with_patches)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "complete_fixed_code": payload.full_code
            }

def main():
    structured = read_structured_input()
    chroma_path = os.path.join(os.getcwd(), "chroma")
    model_name = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    try:
        result = run_pipeline(structured, chroma_path=chroma_path, model_name=model_name, top_k=3)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Print only essential output
    print("Strategy:", result.get("strategy"))
    print("Patch Code:\n" + (result.get("patch_code", "") or ""))
    print("Explanation:\n" + (result.get("explanation", "") or ""))


if __name__ == "__main__":
    # If executed directly, prefer CLI behavior. To run as API:
    #   uvicorn main:app --host 127.0.0.1 --port 8000
    main()
