"""
GARUD-AI — Base Agent
Shared LLM initialization and utilities for all 8 agents.
"""
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("garud_ai.agents")


def get_llm():
    """Return a configured Groq LLM instance, or None if not configured."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or api_key.startswith("your_"):
        return None
    try:
        from langchain_groq import ChatGroq
        return ChatGroq(temperature=0.1, model_name="llama3-70b-8192", max_tokens=2048)
    except Exception as e:
        logger.warning(f"Failed to initialize Groq LLM: {e}")
        return None


def call_llm_json(llm, prompt: str, fallback: dict) -> dict:
    """Call LLM with a prompt expecting JSON output. Returns fallback on failure."""
    if not llm:
        return fallback
    try:
        from langchain_core.messages import HumanMessage
        response = llm.invoke([HumanMessage(content=prompt)])
        text = response.content.strip()
        # Extract JSON block if wrapped in markdown
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        return json.loads(text)
    except Exception as e:
        logger.warning(f"LLM call failed: {e}")
        return fallback
