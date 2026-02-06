import os
import re
import numpy as np
import pandas as pd
import joblib
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from scipy.sparse import hstack, csr_matrix
from sentence_transformers import SentenceTransformer

MODEL_DIR = 'model'
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_FILES = {
    'model': os.path.join(MODEL_DIR, 'best_rf_model.pkl'),
    'label_encoder': os.path.join(MODEL_DIR, 'label_encoder.pkl'),
    'vectorizer': os.path.join(MODEL_DIR, 'vectorizer.pkl'),
    'scaler': os.path.join(MODEL_DIR, 'scaler.pkl'),
    'feature_names': os.path.join(MODEL_DIR, 'feature_names.pkl'),
    'nlp_processor': os.path.join(MODEL_DIR, 'nlp_processor.pkl'),
    'embedding_cache': os.path.join(MODEL_DIR, 'embeddings.npy')
}

class NLPProcessor:
    def __init__(self):
        print("[i] Loading spaCy and SentenceTransformer models...")
        self.nlp = spacy.load("en_core_web_sm")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
    def extract_features(self, command):
        doc = self.nlp(command)
        return {
            'num_verbs': sum(1 for token in doc if token.pos_ == "VERB"),
            'num_nouns': sum(1 for token in doc if token.pos_ == "NOUN"),
            'num_entities': len(doc.ents),
            'has_file_path': any(token.text.startswith(('/','./','../')) for token in doc),
            'command_length': len(command),
            'special_chars': sum(1 for c in command if c in {';', '|', '&', '$', '>'}),
            # New feature: detect base64 strings (simple heuristic)
            'has_base64': int(bool(re.search(r'([A-Za-z0-9+/=]{20,})', command))),
            # New feature: detect hex encoding
            'has_hex': int(bool(re.search(r'(\\x[a-fA-F0-9]{2})', command))),
        }
    
    def get_embedding(self, command):
        return self.embedder.encode([command], convert_to_numpy=True)[0]

def load_dataset(path: str) -> pd.DataFrame:
    print(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset file not found: {path}")
    df = pd.read_excel(path)
    
    required_columns = ['prompt', 'Label', 'Score'] + [
        'Lolbin (0.05)', 'Content (0.4)', 'Frequency (0.2)',
        'Source (0.1)', 'Network (0.1)', 'Behavioural (0.1)', 'History (0.05)'
    ]
    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' not found in dataset")
    
    return df

def create_feature_transformers():
    return {
        'vectorizer': TfidfVectorizer(max_features=10000),
        'scaler': StandardScaler()
    }

def get_or_cache_embeddings(commands, nlp_processor, cache_path):
    if os.path.exists(cache_path):
        embeddings = np.load(cache_path)
        if len(embeddings) != len(commands):
            print("[!] Cached embeddings mismatch with current dataset. Recomputing...")
            embeddings = np.array([nlp_processor.get_embedding(cmd) for cmd in commands], dtype='float64')
            np.save(cache_path, embeddings)
    else:
        print("[i] Computing embeddings (this may take a while)...")
        embeddings = np.array([nlp_processor.get_embedding(cmd) for cmd in commands], dtype='float64')
        np.save(cache_path, embeddings)
    return embeddings


def extract_features(df, transformers, nlp_processor, mode='train'):
    text_cols = [
        'Lolbin (0.05)', 'Content (0.4)', 'Frequency (0.2)',
        'Source (0.1)', 'Network (0.1)', 'Behavioural (0.1)', 'History (0.05)'
    ]
    
    for col in text_cols:
        df[col] = df[col].fillna('none').astype(str)
    combined_text = df[text_cols].agg(' '.join, axis=1)
    
    if mode == 'train':
        X_text = transformers['vectorizer'].fit_transform(combined_text)
        print(f"[TRAIN] Vectorizer vocab size: {len(transformers['vectorizer'].vocabulary_)}")  # <-- Add here
    else:
        X_text = transformers['vectorizer'].transform(combined_text)

    df['prompt'] = df['prompt'].astype(str)
    numeric_features = pd.DataFrame({
        'cmd_length': df['prompt'].apply(len).astype('float64'),
        'special_count': df['prompt'].str.count(r"[;|&%$<>]").astype('float64'),
        'score': df['Score'].fillna(0).astype('float64')
    })
    
    linguistic_features = pd.DataFrame([nlp_processor.extract_features(cmd) for cmd in df['prompt']]).astype('float64')
    rule_based_features = pd.DataFrame([extract_rule_based_features(cmd) for cmd in df['prompt']]).astype('float64')

    if mode == 'train':
        X_numeric = transformers['scaler'].fit_transform(numeric_features)
    else:
        X_numeric = transformers['scaler'].transform(numeric_features)
    
    embeddings = get_or_cache_embeddings(df['prompt'], nlp_processor, MODEL_FILES['embedding_cache'])
    
    X = hstack([
        X_text,
        csr_matrix(embeddings, dtype='float64'),
        csr_matrix(linguistic_features, dtype='float64'),
        csr_matrix(rule_based_features, dtype='float64'),  # Add rule-based features here
        csr_matrix(X_numeric, dtype='float64')
    ])

    total_features = (
        X_text.shape[1] +
        embeddings.shape[1] +
        linguistic_features.shape[1] +
        rule_based_features.shape[1] +
        X_numeric.shape[1]
    )
    print(f"[DEBUG] Total computed features: {total_features}")
    print(f"[DEBUG] Combined features shape: {X.shape}")
    assert X.shape[1] == total_features, "Mismatch in combined feature count"
        
    text_feature_names = transformers['vectorizer'].get_feature_names_out().tolist()
    numeric_feature_names = numeric_features.columns.tolist()
    linguistic_feature_names = linguistic_features.columns.tolist()
    embedding_feature_names = [f'embed_{i}' for i in range(embeddings.shape[1])]
    rule_based_feature_names = rule_based_features.columns.tolist()
    
    all_feature_names = (
        text_feature_names +
        embedding_feature_names +
        linguistic_feature_names +
        rule_based_feature_names +   
        numeric_feature_names
    )
        
    # === Preprocessing check: print samples ===
    if mode == 'train':
        print("\n[i] Sample combined text for TF-IDF:")
        print(combined_text.head(3).to_list())
        print("\n[i] Sample numeric features:")
        print(numeric_features.head(3))
        print("\n[i] Sample linguistic features (including new obfuscation features):")
        print(linguistic_features.head(3))
        print("\n[i] Embeddings shape:", embeddings.shape)
    
    return X, all_feature_names, numeric_feature_names

def extract_rule_based_features(command: str) -> dict:
    import re
    features = {
        'contains_lolbin': int(bool(re.search(r'(powershell|cmd|wmic|schtasks)', command, re.I))),
        'contains_base64': int(bool(re.search(r'([A-Za-z0-9+/=]{20,})', command))),
        'contains_hex': int(bool(re.search(r'(\\x[a-fA-F0-9]{2})', command))),
        'contains_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', command))),
        'contains_url': int(bool(re.search(r'(https?://|http://|ftp://)', command))),
    }
    return features

def evaluate_model(model, X_test, y_test, label_encoder):
    print("\n[+] Model Evaluation on Test Set:")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")

def cross_validation_score(model, X, y):
    print("[i] Performing 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy', n_jobs=-1)
    print("CV Accuracy scores:", scores)
    print(f"Mean CV accuracy: {scores.mean():.4f}")

def hyperparameter_tuning(X_train, y_train):
    print("[i] Starting hyperparameter tuning using GridSearchCV...")
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 20, 40],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'class_weight': ['balanced', None]
    }
    
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    grid_search = GridSearchCV(rf, param_grid, cv=3, scoring='accuracy', n_jobs=-1, verbose=2)
    grid_search.fit(X_train, y_train)
    
    print(f"[✓] Best params: {grid_search.best_params_}")
    print(f"[✓] Best CV accuracy: {grid_search.best_score_:.4f}")
    return grid_search.best_estimator_

def train_and_save_model():
    print("[i] Loading dataset...")
    df = load_dataset('cmd_dataset.xlsx')
    
    print("[i] Initializing NLP processor...")
    nlp_processor = NLPProcessor()
    
    print("[i] Initializing feature transformers...")
    transformers = create_feature_transformers()
    
    print("[i] Extracting features...")
    X, feature_names, numeric_feature_names = extract_features(df, transformers, nlp_processor, mode='train')
    print(f"[i] Final feature matrix shape: {X.shape}")

    print(f"[DEBUG] Training features shape: {X.shape}")
    print(f"[DEBUG] Number of feature names: {len(feature_names)}")

    joblib.dump(feature_names, MODEL_FILES['feature_names'])
    joblib.dump(numeric_feature_names, os.path.join(MODEL_DIR, 'numeric_feature_names.pkl'))

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['Label'].astype(str).str.lower().str.strip())
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    best_model = hyperparameter_tuning(X_train, y_train)
    
    evaluate_model(best_model, X_test, y_test, label_encoder)
    
    cross_validation_score(best_model, X, y)
    
    print("[i] Saving model and transformers...")
    joblib.dump(best_model, MODEL_FILES['model'])
    joblib.dump(label_encoder, MODEL_FILES['label_encoder'])
    joblib.dump(transformers['vectorizer'], MODEL_FILES['vectorizer'])
    joblib.dump(transformers['scaler'], MODEL_FILES['scaler'])
    joblib.dump(feature_names, MODEL_FILES['feature_names'])
    joblib.dump(nlp_processor, MODEL_FILES['nlp_processor'])
    print("\n[✓] Training and tuning completed successfully!")
    print(f"Saved model and components to '{MODEL_DIR}' directory")

if __name__ == '__main__':
    train_and_save_model()
