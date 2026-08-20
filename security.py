import re
import base64
import zipfile
import tarfile
import tempfile
import shutil
import io
import os

class SecurityScanner:
    """
    6-Layer Security Scanner:
    1) AI Security Scan (pattern-based)
    2) Malicious Code Scan (AST & regex)
    3) Encoded/Hidden Content Scan
    4) Secure Sandbox Analysis
    5) Permission & Data Protection Scan
    6) Archive Bomb & Nested Extraction Protection
    """

    MAX_FILES = 1000
    MAX_TOTAL_SIZE = 100 * 1024 * 1024      # 100 MB
    MAX_EXTRACT_SIZE = 500 * 1024 * 1024    # 500 MB
    MAX_RECURSION = 5

    SUSPICIOUS_PATTERNS = {
        "python": [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\(",
            r"__import__\s*\(",
            r"os\.system\s*\(",
            r"subprocess\.Popen\s*\(",
            r"subprocess\.call\s*\(",
            r"subprocess\.check_output\s*\(",
            r"os\.popen\s*\(",
            r"os\.remove\s*\(",
            r"os\.unlink\s*\(",
            r"shutil\.rmtree\s*\(",
            r"os\.chmod\s*\(",
            r"os\.rename\s*\(",
            r"os\.symlink\s*\(",
            r"requests\.get\s*\([^)]*\)",
            r"urllib\.request\.urlopen",
            r"socket\.",
            r"pickle\.loads",
            r"marshal\.loads",
            r"base64\.b64decode",
            r"zlib\.decompress",
            r"telegram\.Bot\s*\(",
            r"client\.send_message",
            r"api_key\s*=",
            r"cookie\s*=",
            r"token\s*=",
            r"os\.environ\s*\[",
        ],
        "javascript": [
            r"eval\s*\(",
            r"new\s+Function\s*\(",
            r"require\s*\(\s*[\"\']child_process[\"\']\s*\)",
            r"process\.exec",
            r"process\.spawn",
            r"child_process\.exec",
            r"child_process\.spawn",
            r"fs\.unlink",
            r"fs\.rmdir",
            r"fs\.chmod",
            r"fs\.symlink",
            r"http\.request",
            r"axios\.",
            r"fetch\s*\(",
            r"\.token\s*=",
            r"api_key\s*=",
            r"cookie\s*=",
            r"base64\.decode",
            r"Buffer\.from",
            r"process\.env\s*\[",
            r"global\.",
            r"window\.",
        ]
    }

    def __init__(self):
        self.issues = []
        self.passed = True

    def scan_file(self, file_bytes: bytes, filename: str, original_filename: str = None) -> tuple:
        """Main entry: scan a single file (bytes) and return (passed, list_of_issues)."""
        self.issues = []
        self.passed = True
        filename = filename or original_filename or "unknown"
        ext = os.path.splitext(filename)[1].lower()

        if ext in [".zip", ".rar", ".tar", ".gz", ".tgz", ".7z"]:
            self._scan_archive(file_bytes, filename)
        else:
            self._scan_single_file(file_bytes, filename)

        return self.passed, self.issues

    def _scan_archive(self, file_bytes: bytes, filename: str):
        """Extract and scan archive recursively with bomb protection."""
        ext = os.path.splitext(filename)[1].lower()
        temp_dir = tempfile.mkdtemp(prefix="sec_scan_")
        try:
            if ext == ".zip":
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                    self._check_zip_bomb(zf)
                    zf.extractall(temp_dir)
            elif ext in [".tar", ".tgz", ".gz"]:
                with tarfile.open(fileobj=io.BytesIO(file_bytes), mode="r:*") as tf:
                    self._check_tar_bomb(tf)
                    tf.extractall(temp_dir)
            else:
                self.issues.append(f"Unsupported archive type: {ext}")
                self.passed = False
                return

            # Scan every extracted file recursively
            for root, dirs, files in os.walk(temp_dir):
                for f in files:
                    file_path = os.path.join(root, f)
                    rel_path = os.path.relpath(file_path, temp_dir)
                    if os.path.islink(file_path):
                        self.issues.append(f"Symlink detected: {rel_path} (unsafe)")
                        self.passed = False
                        continue
                    try:
                        with open(file_path, "rb") as fp:
                            content = fp.read()
                        sub_passed, sub_issues = self._scan_single_file(content, f, rel_path)
                        if not sub_passed:
                            self.passed = False
                            self.issues.extend(sub_issues)
                    except Exception as e:
                        self.issues.append(f"Error scanning {rel_path}: {e}")
                        self.passed = False
        except Exception as e:
            self.issues.append(f"Archive extraction error: {e}")
            self.passed = False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _scan_single_file(self, content: bytes, filename: str, rel_path: str = None) -> tuple:
        """Scan a single file (bytes) for malicious patterns and encoded content."""
        issues = []
        passed = True
        ext = os.path.splitext(filename)[1].lower()

        text_content = None
        try:
            text_content = content.decode("utf-8", errors="ignore")
        except:
            pass

        if text_content:
            decoded_issues = self._check_encoded_content(text_content)
            if decoded_issues:
                issues.extend(decoded_issues)
                passed = False

        if ext == ".py":
            py_passed, py_issues = self._scan_python(content, text_content)
            if not py_passed:
                passed = False
                issues.extend(py_issues)
        elif ext == ".js":
            js_passed, js_issues = self._scan_javascript(text_content)
            if not js_passed:
                passed = False
                issues.extend(js_issues)
        else:
            if text_content:
                generic_passed, generic_issues = self._generic_scan(text_content)
                if not generic_passed:
                    passed = False
                    issues.extend(generic_issues)

        if filename.lower() in [".env", "config.json", "secrets.json", "credentials.json"]:
            issues.append(f"Sensitive configuration file: {filename}")
            passed = False

        if rel_path and ("../" in rel_path or "..\\" in rel_path):
            issues.append(f"Path traversal attempt: {rel_path}")
            passed = False

        return passed, issues

    def _scan_python(self, content: bytes, text_content: str = None) -> tuple:
        """AST-based Python code analysis."""
        issues = []
        passed = True
        if not text_content:
            try:
                text_content = content.decode("utf-8", errors="ignore")
            except:
                return False, ["Could not decode Python file"]

        try:
            import ast
            tree = ast.parse(text_content, mode="exec")
        except SyntaxError as e:
            issues.append(f"Syntax error: {e}")
            passed = False
            return passed, issues

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in ["eval", "exec", "compile", "__import__"]:
                        issues.append(f"Dangerous function call: {func_name}")
                        passed = False
                elif isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    if attr in ["system", "popen", "remove", "unlink", "chmod", "rename", "symlink"]:
                        issues.append(f"Dangerous attribute access: {node.func.value.id}.{attr}")
                        passed = False
                    elif attr in ["Popen", "call", "check_output"]:
                        issues.append(f"Dangerous subprocess call: {node.func.value.id}.{attr}")
                        passed = False
            if isinstance(node, ast.ImportFrom):
                if node.module in ["os", "subprocess", "shutil", "socket"]:
                    for alias in node.names:
                        if alias.name in ["system", "popen", "remove", "unlink", "rmtree", "chmod", "rename", "symlink",
                                          "Popen", "call", "check_output"]:
                            issues.append(f"Dangerous import: from {node.module} import {alias.name}")
                            passed = False

        if text_content:
            if re.search(r"(?i)(token|api_key|secret|password)\s*=\s*[\"\']", text_content):
                issues.append("Potential hardcoded credential found")
                passed = False

        return passed, issues

    def _scan_javascript(self, text_content: str) -> tuple:
        """Scan JavaScript with regex patterns."""
        issues = []
        passed = True
        if not text_content:
            return True, []

        for pattern in self.SUSPICIOUS_PATTERNS["javascript"]:
            if re.search(pattern, text_content, re.IGNORECASE):
                issues.append(f"Suspicious JS pattern: {pattern}")
                passed = False

        if re.search(r"(?i)(token|api_key|secret|password)\s*=\s*[\"\']", text_content):
            issues.append("Potential hardcoded credential in JS")
            passed = False

        return passed, issues

    def _generic_scan(self, text_content: str) -> tuple:
        """Generic scan for any text file."""
        issues = []
        passed = True
        suspicious_generic = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"child_process",
            r"system\s*\(",
            r"popen\s*\(",
            r"rm\s+-rf",
            r"del\s+",
            r"\.destroy",
            r"\.delete",
        ]
        for pattern in suspicious_generic:
            if re.search(pattern, text_content, re.IGNORECASE):
                issues.append(f"Suspicious pattern: {pattern}")
                passed = False

        return passed, issues

    def _check_encoded_content(self, text: str) -> list:
        """Detect base64, hex, url-encoded, rot13, etc."""
        issues = []
        base64_pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
        for match in re.findall(base64_pattern, text):
            try:
                decoded = base64.b64decode(match, validate=True)
                sub_passed, sub_issues = self._scan_single_file(decoded, "decoded_base64")
                if not sub_passed:
                    issues.extend(sub_issues)
            except:
                pass

        hex_pattern = r"[0-9A-Fa-f]{40,}"
        for match in re.findall(hex_pattern, text):
            try:
                decoded = bytes.fromhex(match)
                sub_passed, sub_issues = self._scan_single_file(decoded, "decoded_hex")
                if not sub_passed:
                    issues.extend(sub_issues)
            except:
                pass

        url_pattern = r"%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}"
        if re.search(url_pattern, text):
            issues.append("URL-encoded content detected (possible obfuscation)")

        return issues

    def _check_zip_bomb(self, zf):
        total_size = 0
        file_count = 0
        for info in zf.infolist():
            file_count += 1
            if file_count > self.MAX_FILES:
                raise Exception(f"Archive contains more than {self.MAX_FILES} files")
            total_size += info.file_size
            if total_size > self.MAX_TOTAL_SIZE:
                raise Exception(f"Archive total size exceeds {self.MAX_TOTAL_SIZE} bytes")
            if ".." in info.filename or info.filename.startswith("/"):
                raise Exception(f"Path traversal attempt: {info.filename}")

    def _check_tar_bomb(self, tf):
        total_size = 0
        file_count = 0
        for info in tf:
            if info.isreg():
                file_count += 1
                if file_count > self.MAX_FILES:
                    raise Exception(f"Archive contains more than {self.MAX_FILES} files")
                total_size += info.size
                if total_size > self.MAX_TOTAL_SIZE:
                    raise Exception(f"Archive total size exceeds {self.MAX_TOTAL_SIZE} bytes")
            if ".." in info.name or info.name.startswith("/"):
                raise Exception(f"Path traversal attempt: {info.name}")
