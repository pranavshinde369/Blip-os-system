import chromadb
from chromadb.config import Settings  # <--- NEW IMPORT
from sentence_transformers import SentenceTransformer
import os

# --- CONFIGURATION ---
MODEL_NAME = "all-MiniLM-L6-v2"
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'vector_db')
SIMILARITY_THRESHOLD = 0.45 

class EnterpriseRAG:
    def __init__(self):
        print("⚡ Loading Enterprise RAG Engine (Embeddings)...")
        
        self.model = SentenceTransformer(MODEL_NAME)
        
        # --- FIXED: DISABLE TELEMETRY ---
        self.client = chromadb.PersistentClient(
            path=DB_PATH,
            settings=Settings(anonymized_telemetry=False) # Stops the errors
        )
        
        self.collection = self.client.get_or_create_collection(name="restricted_codebase")
        
        if self.collection.count() == 0:
            self._load_mock_secrets()

    def _load_mock_secrets(self):
        """
        Loads fake 'Proprietary Company Code' into the database.
        """
        print("🔒 Indexing Secret Company Codebase...")
        
        secrets = [
            # Secret 1: Google-style Search Logic
            """
            def compute_pagerank(graph, damping=0.85):
                ranks = {node: 1/len(graph) for node in graph}
                for _ in range(10):
                    new_ranks = {}
                    for node in graph:
                        rank_sum = sum(ranks[n] / len(graph[n]) for n in graph if node in graph[n])
                        new_ranks[node] = (1 - damping) / len(graph) + damping * rank_sum
                    ranks = new_ranks
                return ranks
            """,
            
            # Secret 2: Authentication Logic
            """
            class InternalAuth:
                SECRET_SALT = "super_secret_salt_v2"
                def generate_token(self, user_id):
                    return hashlib.sha256(f"{user_id}{self.SECRET_SALT}".encode()).hexdigest()
            """,
            
            # Secret 3: Proprietary Trading Algorithm
            """
            def execute_high_freq_trade(symbol, threshold):
                price = get_live_price(symbol)
                if price < threshold * 0.98:
                    buy_order(symbol, leverage=10)
                elif price > threshold * 1.02:
                    sell_order(symbol)
            """
        ]
        
        ids = [f"secret_{i}" for i in range(len(secrets))]
        
        embeddings = self.model.encode(secrets).tolist()
        self.collection.add(documents=secrets, embeddings=embeddings, ids=ids)
        print(f"✅ Indexed {len(secrets)} restricted code blocks.")

    def check_for_leaks(self, clipboard_text):
        if len(clipboard_text) < 30:
            return False, None

        query_embedding = self.model.encode([clipboard_text]).tolist()
        
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=1
        )
        
        if results['distances'] and len(results['distances'][0]) > 0:
            distance = results['distances'][0][0]
            if distance < SIMILARITY_THRESHOLD:
                matched_snippet = results['documents'][0][0][:50] + "..."
                return True, f"Matches Internal Codebase (Dist: {distance:.2f})\nRef: {matched_snippet}"

        return False, None

# Global Instance
rag_system = None

def get_rag_engine():
    global rag_system
    if rag_system is None:
        rag_system = EnterpriseRAG()
    return rag_system