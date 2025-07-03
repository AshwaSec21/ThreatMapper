from sentence_transformers import SentenceTransformer, util

class RequirementVectorSearch:
    def __init__(self, requirements: list[dict]):
        self.requirements = requirements
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.embeddings = self.model.encode(
            [self._enrich_text(r) for r in requirements], convert_to_tensor=True
        )

    def _enrich_text(self, req: dict) -> str:
        return f"{req['text']} Asset: {req['assets']}"

    def get_top_k_matches(self, threat: dict, k: int = 5) -> list[str]:
        """
        For a single threat, return top k matching requirement IDs based on semantic similarity.
        """
        threat_assets = threat.get("Interaction", "")
        threat_text = (
            f"{threat['Title']} {threat['Description']} Asset: {threat_assets}"
        )
        threat_embedding = self.model.encode(threat_text, convert_to_tensor=True)

        cosine_scores = util.cos_sim(threat_embedding, self.embeddings)[0]
        top_k = min(k, len(self.requirements))
        top_results = cosine_scores.topk(top_k)

        return [self.requirements[i]["id"] for i in top_results.indices]
