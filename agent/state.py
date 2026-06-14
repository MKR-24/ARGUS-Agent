from typing import Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from typing_extensions import TypedDict


class AgentState(TypedDict):
    """
    State that flows through every node in the graph.
    messages accumulates with add_messages reducer —
    new messages are appended, not replaced.
    """

    messages: Annotated[list[BaseMessage], add_messages]
    alert_id: str
    service_id: str
    cve_id: str | None
