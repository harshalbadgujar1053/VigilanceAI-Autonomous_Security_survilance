"""
map_to_mitre.py — Tool 2 for Vigilance AI ReAct Agent
------------------------------------------------------
Maps a security alert to specific MITRE ATT&CK techniques
by combining ChromaDB semantic search with Mistral reasoning.

Difference from lookup_threat_intel:
- lookup_threat_intel: returns raw search results (fast)
- map_to_mitre: searches + asks LLM to confirm + explain mapping (richer)
"""

from langchain.tools import tool
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
import chromadb
from chromadb.utils import embedding_functions


def get_collection():
    client = chromadb.PersistentClient(
        path="/home/kali/vigilance-ai/agent/chroma_db"
    )
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    return client.get_collection(
        name="mitre_techniques",
        embedding_function=embed_fn
    )


MAPPING_PROMPT = PromptTemplate(
    input_variables=["alert_description", "mitre_candidates"],
    template="""You are a cybersecurity expert mapping security alerts to MITRE ATT&CK.

Alert description: {alert_description}

Candidate MITRE techniques retrieved from database:
{mitre_candidates}

Based on the alert and candidates above, identify the BEST matching
MITRE technique(s). Be concise.

Respond in this format:
PRIMARY TECHNIQUE: <ID> - <Name>
CONFIDENCE: <High|Medium|Low>
REASON: <one sentence explaining why this technique matches>
SECONDARY TECHNIQUE (if applicable): <ID> - <Name>
"""
)


@tool
def map_to_mitre(alert_description: str) -> str:
    """
    Map a security alert description to the most relevant MITRE ATT&CK
    technique(s). Uses semantic search to find candidates, then uses
    the LLM to confirm the best match with reasoning.

    Use this tool when you need to:
    - Formally identify which MITRE technique an alert represents
    - Get a confident, reasoned technique mapping for a report
    - Understand the tactic category (Initial Access, Persistence, etc.)

    Args:
        alert_description: Plain text description of the alert or
                          suspicious activity to map.
                          Example: "847 failed SSH logins in 60 seconds
                          from IP 185.220.101.47"

    Returns:
        Primary MITRE technique ID, name, confidence level,
        and reasoning for the mapping.
    """
    try:
        # Step 1: Get candidates from ChromaDB
        collection = get_collection()
        results = collection.query(
            query_texts=[alert_description],
            n_results=3
        )

        candidates_text = ""
        for i, technique_id in enumerate(results["ids"][0]):
            name = results["metadatas"][0][i]["technique"]
            text = results["documents"][0][i][:300]
            candidates_text += f"[{technique_id}] {name}: {text}\n\n"

        # Step 2: Ask Mistral to confirm the best match
        llm = OllamaLLM(model="mistral", temperature=0)
        chain = MAPPING_PROMPT | llm | StrOutputParser()

        result = chain.invoke({
            "alert_description": alert_description,
            "mitre_candidates": candidates_text
        })

        return result

    except Exception as e:
        return f"Error mapping to MITRE: {str(e)}"


if __name__ == "__main__":
    print("Testing map_to_mitre tool...")
    print("─" * 50)

    result = map_to_mitre.invoke(
        "847 failed SSH login attempts in 60 seconds from external IP 185.220.101.47"
    )
    print(result)
