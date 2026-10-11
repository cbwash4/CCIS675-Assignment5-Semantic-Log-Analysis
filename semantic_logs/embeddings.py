"""The same model and normalization must be used for indexing and querying."""
import numpy as np

MODEL_NAME = 'sentence-transformers/all-MiniLM-L6-v2'
DIMENSION = 384


class MiniLMEncoder:
    model_name = MODEL_NAME

    def __init__(self, device=None):
        from huggingface_hub import hf_hub_download
        from sentence_transformers import SentenceTransformer
        # Require the actual SentenceTransformer configuration. Do not silently
        # fall back to a newly constructed pooling pipeline on download failure.
        hf_hub_download(MODEL_NAME, 'modules.json')
        # SentenceTransformer selects CUDA when available, otherwise CPU.
        self.model = SentenceTransformer(MODEL_NAME, device=device)
        if self.model.get_sentence_embedding_dimension() != DIMENSION:
            raise ValueError('MiniLM must produce 384-dimensional embeddings')
        self.device = str(self.model.device)

    def encode(self, texts, batch_size=64):
        if batch_size < 1:
            raise ValueError('batch_size must be positive')
        vectors = self.model.encode(list(texts), batch_size=batch_size,
                                    normalize_embeddings=False, show_progress_bar=False)
        return validate_vectors(vectors, len(texts))


def validate_vectors(vectors, count):
    array = np.asarray(vectors, dtype=np.float32)
    if array.shape != (count, DIMENSION) or not np.isfinite(array).all():
        raise ValueError(f'Expected {count} finite {DIMENSION}-dimensional embeddings')
    return array
