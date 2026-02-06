import pandas as pd
import numpy as np
import joblib
import os
import re
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sentence_transformers import SentenceTransformer
from scipy.sparse import hstack, csr_matrix
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.prompt import Prompt
from pprint import pprint
import traceback

console = Console()

from alerts import handle_log_selection
from logger import secure_log, view_logs, load_full_analysis_log
from display import show_main_menu, display_results_improved
from analyser import run_ai_analysis, run_threat_intel, print_structured_ai_analysis, print_threat_intel_grouped
from collections import defaultdict

# === Constants ===
MODEL_DIR = 'model'
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_FILES = {
    'model': os.path.join(MODEL_DIR, 'best_rf_model.pkl'),
    'label_encoder': os.path.join(MODEL_DIR, 'label_encoder.pkl'),
    'vectorizer': os.path.join(MODEL_DIR, 'vectorizer.pkl'),
    'scaler': os.path.join(MODEL_DIR, 'scaler.pkl'),
    'feature_names': os.path.join(MODEL_DIR, 'feature_names.pkl')
}

import re
import spacy
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack, csr_matrix
from sentence_transformers import SentenceTransformer
import joblib
from collections import defaultdict

# === Constants ===
MALICIOUS_PATTERNS = {
    'suspicious_redirect': [r'>\s*[\w\.]+', r'>>\s*[\w\.]+'],
    'command_chaining': [r';\s*\w+', r'&&\s*\w+', r'\|\|\s*\w+', r'\|\s*\w+'],
    'sensitive_access': [r'/etc/passwd', r'/etc/shadow', r'/bin/bash', r'/bin/sh'],
    'obfuscation': [r'\$\{[^\}]+\}', r'\$\([^\)]+\)', r'\\x[0-9a-fA-F]{2,}'],
    'network_misuse': [r'wget\s+http', r'curl\s+http', r'nc\s+-l'],
    'privilege_escalation': [r'sudo\s+\w+', r'su\s+\w+', r'chmod\s+[0-7]{3,4}'],
    'data_exfiltration': [r'ssh\s+\w+@\w+\s+<', r'nc\s+\w+\s+\d+\s+<'],
    'malicious_tools': [r'nmap', r'hydra', r'sqlmap', r'metasploit'],
    'base64_long': [r'[A-Za-z0-9+/]{40,}={0,2}'],
    'powershell_flags': [r'-NoProfile', r'-WindowStyle Hidden', r'-Command', r'-enc'],
    'malware_filenames': [r'(?:evilscript|backdoor|payload|dropper)\.(exe|ps1|bat|vbs)'],
    'shell_injection': [r'[;&|]{2,}']
}

TOOL_LIST = ["curl", "wget", "nmap", "certutil", "powershell", "python", "Invoke-WebRequest"]
INTENT_MAP = {
    "Invoke-WebRequest": "Download",
    "nmap": "Recon",
    "certutil": "Download",
    "reg add": "Persistence",
    "netstat": "Enumeration",
}

from scipy.sparse import hstack, csr_matrix
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

def create_hybrid_features(df, nlp_processor, mode='train', vectorizer=None, scaler=None):
    rule_features = pd.DataFrame([extract_rule_features(cmd) for cmd in df['prompt']])
    rule_features = rule_features.fillna(False).astype('float64')

    expected_rule_features = list(MALICIOUS_PATTERNS.keys())
    for feat in expected_rule_features:
        if feat not in rule_features.columns:
            rule_features[feat] = 0.0
    rule_features = rule_features[expected_rule_features]

    linguistic_features = pd.DataFrame(
        [nlp_processor.extract_linguistic_features(cmd) for cmd in df['prompt']]
    ).astype('float64')

    embeddings = np.array(
        [nlp_processor.get_embedding(cmd) for cmd in df['prompt']],
        dtype='float64'
    )

    text_cols = [
        'Lolbin (0.05)', 'Content (0.4)', 'Frequency (0.2)',
        'Source (0.1)', 'Network (0.1)', 'Behavioural (0.1)', 'History (0.05)'
    ]
    combined_text = df[text_cols].fillna('none').astype(str).agg(' '.join, axis=1)

    numeric_features = pd.DataFrame({
        'cmd_length': df['prompt'].apply(len).astype('float64'),
        'special_count': df['prompt'].str.count(r"[;|&%$<>]").astype('float64'),
        'score': df['Score'].fillna(0).astype('float64')
    })

    if mode == 'train':
        vectorizer = TfidfVectorizer(max_features=10000, dtype=np.float64)
        X_text = vectorizer.fit_transform(combined_text)
        scaler = StandardScaler()
        X_numeric = scaler.fit_transform(numeric_features)
    else:
        if vectorizer is None or scaler is None:
            raise ValueError("Transformers must be provided in prediction mode")
        X_text = vectorizer.transform(combined_text)
        X_numeric = scaler.transform(numeric_features)

    def to_csr(x):
        if isinstance(x, pd.DataFrame):
            return csr_matrix(x.values, dtype='float64')
        elif isinstance(x, np.ndarray):
            return csr_matrix(x, dtype='float64')
        else:
            return csr_matrix(x, dtype='float64')

    combined_features = hstack([
        X_text,
        to_csr(embeddings),
        to_csr(linguistic_features),
        to_csr(rule_features),
        to_csr(X_numeric)
    ])

    total_features = (
        X_text.shape[1] +
        embeddings.shape[1] +
        linguistic_features.shape[1] +
        rule_features.shape[1] +
        X_numeric.shape[1]
    )

    return combined_features, vectorizer, scaler

# === NLP Engine ===
class NLPProcessor:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')

    def extract_linguistic_features(self, command):
        doc = self.nlp(command)
        return {
            'num_verbs': sum(1 for token in doc if token.pos_ == "VERB"),
            'num_nouns': sum(1 for token in doc if token.pos_ == "NOUN"),
            'num_entities': len(doc.ents),
            'has_file_path': any(token.text.startswith(('/', './', '../')) for token in doc),
            'command_length': len(command),
            'special_chars': sum(1 for c in command if c in {';', '|', '&', '$', '>'})
        }

    def get_embedding(self, command):
        return self.embedder.encode([command])[0]  # numpy array

# === Feature Extraction ===
def extract_rule_features(command):
    return {cat: any(re.search(p, command, re.IGNORECASE) for p in pats) for cat, pats in MALICIOUS_PATTERNS.items()}

def extract_entities(command, nlp):
    doc = nlp(command)
    return {
        'main_action': next((t.lemma_ for t in doc if t.pos_ == 'VERB'), None),
        'verbs': [t.text for t in doc if t.pos_ == 'VERB'],
        'nouns': [t.text for t in doc if t.pos_ == 'NOUN'],
        'tools': [tool for tool in TOOL_LIST if tool in command.lower()],
        'intent': next((INTENT_MAP[tool] for tool in TOOL_LIST if tool in command.lower() and tool in INTENT_MAP), None)
    }

def detect_regex_patterns(command):
    matches = defaultdict(list)

    for category, patterns in MALICIOUS_PATTERNS.items():
        for pat in patterns:
            hits = re.findall(pat, command, re.IGNORECASE)
            for hit in hits:
                matches[category].append((pat, hit))  # store pattern and matched text
    return matches


# === Detection Class ===
class HybridCommandAnalyzer:
    def __init__(self):
        self.model = joblib.load(MODEL_FILES['model'])
        self.label_encoder = joblib.load(MODEL_FILES['label_encoder'])
        self.vectorizer = joblib.load(MODEL_FILES['vectorizer'])
        self.scaler = joblib.load(MODEL_FILES['scaler'])
        self.nlp_processor = NLPProcessor()

    def analyze(self, command):
        rule_features = extract_rule_features(command)
        entities = extract_entities(command, self.nlp_processor.nlp)
        regex_matches = detect_regex_patterns(command)

        regex_hits_list = []
        for category, pat_hits in regex_matches.items():
            for pattern, sample_match in pat_hits:
                regex_hits_list.append((category, pattern, sample_match))

        doc = self.nlp_processor.nlp(command)
        tokens = [token.text for token in doc]

        prediction_vector, _, _ = create_hybrid_features(pd.DataFrame({
            'prompt': [command],
            'Score': [0],
            'Lolbin (0.05)': ['none'],
            'Content (0.4)': ['none'],
            'Frequency (0.2)': ['none'],
            'Source (0.1)': ['none'],
            'Network (0.1)': ['none'],
            'Behavioural (0.1)': ['none'],
            'History (0.05)': ['none']
        }), self.nlp_processor, 'predict', self.vectorizer, self.scaler)

        if prediction_vector.shape[1] != self.model.n_features_in_:
            prediction_vector = prediction_vector[:, :self.model.n_features_in_]

        proba = self.model.predict_proba(prediction_vector)[0]
        pred_idx = int(np.argmax(proba))
        
        result= {
            'command': command,
            'label': self.label_encoder.classes_[pred_idx],
            'confidence': float(proba[pred_idx]),
            'probabilities': dict(zip(self.label_encoder.classes_, proba)),
            'risk_score': round(proba[1] + 0.5 * proba[2], 3),

            'nlp_analysis': entities,
            'feature_tags': {
                'lolbin': next((b for b in ['powershell', 'cmd', 'regsvr32', 'mshta'] if b in command.lower()), None),
                'content_type': 'script_exec' if any(k in command.lower() for k in ['invoke', 'execute']) else 'other',
                'frequency_profile': 'rare' if any(k in command.lower() for k in ['bitsadmin', 'rundll32']) else 'common',
                'behavioral': '+'.join([k for k in ['obfuscation', 'network_misuse', 'privilege_escalation'] if rule_features.get(k)]),
                'source_context': 'script' if command.endswith('.ps1') else 'interactive',
                'history': 'first-seen'
            },
            'regex_analysis': {
                'matched_patterns': regex_hits_list,
                'pattern_descriptions': describe_matched_rules(rule_features)
            },
            'obfuscation_analysis': {
                'base64_strings': re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', command),
                'hex_strings': re.findall(r'0x[a-fA-F0-9]{8,}', command),
                'unicode_usage': any(ord(c) > 127 for c in command),
                'encoding_flags': [f for f in ['-enc', '--EncodedCommand'] if f in command]
            },
            'command_structure': {
                'token_count': len(tokens),
                'starts_with': tokens[0] if tokens else None,
                'contains_flags': any(t.startswith('-') for t in tokens),
                'uses_quotes': any(q in command for q in ['"', "'"]),
                'uses_pipe': '|' in command,
                'uses_redirection': any(c in command for c in ['>', '<', '>>']),
                'uses_logical_operators': [op for op in ['&&', '||', ';'] if op in command]
            },
            'network_indicators': {
                'ip_addresses': re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', command),
                'urls': re.findall(r'https?://[^\s\'"<>]+', command),
                'domains': re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', command)
            }
        }
        return result

def describe_matched_rules(features):
    return [
        desc for key, desc in {
            'obfuscation': "Encoded content or hex obfuscation",
            'network_misuse': "Suspicious network command usage",
            'privilege_escalation': "Privilege escalation attempt",
            'data_exfiltration': "Likely data exfiltration",
            'malicious_tools': "Malware-associated tools used",
            'sensitive_access': "Access to protected files",
            'command_chaining': "Command chaining (e.g., ;, &&)",
            'suspicious_redirect': "Redirects detected"
        }.items() if features.get(key)
    ]

# === Function to Analyse a Command ===
def is_safe_input(command: str) -> bool:
    if not command.strip():
        return False
    
    if len(command) > 1000:
        return False
    
    if '\x00' in command or '\n' in command or '\r' in command:
        return False
    
    allowed_chars = (
        "abcdefghijklmnopqrstuvwxyz"  # letters
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"                  # digits
        " _-.:/\\%"                   # common Windows symbols: space, underscore, dash, dot, colon, slash, backslash, percent
        "\"'`$^&|<>=?*,"             # symbols often used in commands or scripts
    )
    
    return all(c in allowed_chars for c in command)


def analyse_command(analyzer):
    cmd = Prompt.ask("[bold green]Enter command to analyze[/bold green]").strip()
    if cmd.lower() in ('quit', 'exit'):
        return
    if not is_safe_input(cmd):
        console.print("[red]Input rejected due to unsafe characters or length.[/red]")
        return

    # Load cache once (optimize per session if needed)
    cache = load_full_analysis_log()

    if cmd in cache:
        print()
        console.print("[yellow]Found previous analysis in history. Displaying cached result.[/yellow]")
        cached_result = cache[cmd]
        display_results_improved(cached_result)
        print_structured_ai_analysis(cached_result)
        print_threat_intel_grouped(cached_result)
        print()
        return

    try:
        # === Prediction Phase ===
        print()
        result = analyzer.analyze(cmd)
        # pprint(result)
        display_results_improved(result)
        result = run_ai_analysis(result)  # enrich result
        result = run_threat_intel(result)  # enrich result
        secure_log(result)
        print_structured_ai_analysis(result)
        print_threat_intel_grouped(result)
        print()

    except Exception as e:
        console.print(f"[bold red]Analysis failed:[/bold red] {e}")


def analyse_from_file(analyzer):
    console.print("[bold magenta]>> [cyan]Analyse from File[/cyan] selected.[/bold magenta]")
    file_path = Prompt.ask("[bold yellow]Enter path to command file[/bold yellow]").strip()
    if not os.path.exists(file_path):
        console.print("[red]File not found. Please check the path.[/red]")
        return

    # Load cache once
    cache = load_full_analysis_log()

    try:
        with open(file_path, 'r') as f:
            commands = [line.strip() for line in f if line.strip()]
        for cmd in commands:
            if not is_safe_input(cmd):
                console.print(f"[yellow]Skipped unsafe command:[/yellow] {cmd}")
                continue

            if cmd in cache:
                print()
                console.print(f"[yellow]Cached analysis found for command:[/yellow] {cmd}")
                cached_result = cache[cmd]
                display_results_improved(cached_result)
                print_structured_ai_analysis(cached_result)
                print_threat_intel_grouped(cached_result)
                print()
                continue
            
            print()
            result = analyzer.analyze(cmd)
            display_results_improved(result)
            result = run_ai_analysis(result)
            result = run_threat_intel(result)
            secure_log(result)
            print_structured_ai_analysis(result)
            print_threat_intel_grouped(result)
            print()

        console.print("[green]File analysis completed.[/green]")
    except Exception as e:
        console.print(f"[bold red]Failed to process file:[/bold red] {e}")

# === Main Execution ===
if __name__ == '__main__':
    analyzer = HybridCommandAnalyzer()
    while True:
        show_main_menu()
        try:
            choice = Prompt.ask("\n[bold yellow]Enter your choice[/bold yellow]", choices=["1", "2", "3", "0"])
            if choice == "1":
                analyse_command(analyzer)
            elif choice == "2":
                analyse_from_file(analyzer)
            elif choice == "3":
                handle_log_selection()
            elif choice == "0":
                console.print("\n[bold red]Exiting MalCommandGuard... Stay safe![/bold red]")
                break
        except KeyboardInterrupt:
            console.print("\n[bold red]\n[!] Interrupted by user. Exiting...[/bold red]")
            break
        except Exception as e:
            console.print(f"[bold red]\n[!] An unexpected error occurred: {e}[/bold red]")
            traceback.print_exc()
