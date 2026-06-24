"""
LangGraph workflow builder for agent orchestration.
Provides a high-level API for building agent workflows.
"""

from typing import Any, Callable, Dict, List, Optional, Type, Union
from pydantic import BaseModel
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from .state import AgentState
from .base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from ..core.logging import get_logger

logger = get_logger(__name__)


class WorkflowNode:
    """A node in the workflow graph."""

    def __init__(
        self,
        name: str,
        func: Callable,
        agent: Optional[BaseAgent] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.func = func
        self.agent = agent
        self.metadata = metadata or {}


class WorkflowEdge:
    """An edge in the workflow graph."""

    def __init__(
        self,
        source: str,
        target: str,
        condition: Optional[Callable] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.source = source
        self.target = target
        self.condition = condition
        self.metadata = metadata or {}


class AgentWorkflow:
    """LangGraph workflow for agent orchestration."""

    def __init__(self, name: str, state_schema: Type[AgentState] = AgentState):
        self.name = name
        self.state_schema = state_schema
        self.nodes: Dict[str, WorkflowNode] = {}
        self.edges: List[WorkflowEdge] = []
        self.entry_point: Optional[str] = None
        self.checkpointer = MemorySaver()
        self._graph: Optional[StateGraph] = None

    def add_node(
        self,
        name: str,
        func: Callable,
        agent: Optional[BaseAgent] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AgentWorkflow":
        """Add a node to the workflow."""
        self.nodes[name] = WorkflowNode(name, func, agent, metadata)
        return self

    def add_agent(
        self,
        agent: BaseAgent,
        name: Optional[str] = None,
    ) -> "AgentWorkflow":
        """Add an agent as a node."""
        node_name = name or agent.agent_type.value

        async def agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
            result = await agent.run(state)
            return {
                **state,
                f"{node_name}_result": result.output,
                f"{node_name}_status": result.status.value,
            }

        return self.add_node(node_name, agent_node, agent)

    def add_edge(
        self,
        source: str,
        target: str,
        condition: Optional[Callable] = None,
    ) -> "AgentWorkflow":
        """Add an edge between nodes."""
        self.edges.append(WorkflowEdge(source, target, condition))
        return self

    def set_entry_point(self, node_name: str) -> "AgentWorkflow":
        """Set the entry point node."""
        self.entry_point = node_name
        return self

    def add_conditional_edge(
        self,
        source: str,
        condition: Callable,
        targets: Dict[str, str],
    ) -> "AgentWorkflow":
        """Add a conditional edge."""
        def router(state: Dict[str, Any]) -> str:
            result = condition(state)
            return targets.get(result, END)

        self.edges.append(WorkflowEdge(source, "__router__", condition))
        return self

    def build(self) -> StateGraph:
        """Build the LangGraph workflow."""
        if not self.entry_point:
            raise ValueError("Entry point not set")

        # Create state graph
        self._graph = StateGraph(self.state_schema)

        # Add nodes
        for name, node in self.nodes.items():
            self._graph.add_node(name, node.func)

        # Add edges
        for edge in self.edges:
            if edge.source == "__entry__":
                self._graph.set_entry_point(edge.target)
            elif edge.target == "__end__":
                self._graph.add_edge(edge.source, END)
            elif edge.condition:
                self._graph.add_conditional_edges(
                    edge.source,
                    edge.condition,
                )
            else:
                self._graph.add_edge(edge.source, edge.target)

        # Set entry point
        self._graph.set_entry_point(self.entry_point)

        return self._graph

    def compile(self):
        """Compile the workflow for execution."""
        graph = self.build()
        return graph.compile(checkpointer=self.checkpointer)

    async def run(
        self,
        initial_state: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run the workflow with initial state."""
        compiled = self.compile()
        result = await compiled.ainvoke(initial_state, config)
        return result


class WorkflowBuilder:
    """Builder pattern for creating workflows."""

    def __init__(self, name: str, state_schema: Type[AgentState] = AgentState):
        self.workflow = AgentWorkflow(name, state_schema)

    def with_triage_agent(self, agent: BaseAgent) -> "WorkflowBuilder":
        """Add triage agent."""
        self.workflow.add_agent(agent, "triage")
        return self

    def with_analysis_agent(self, agent: BaseAgent) -> "WorkflowBuilder":
        """Add analysis agent."""
        self.workflow.add_agent(agent, "analysis")
        return self

    def with_threat_intel_agent(self, agent: BaseAgent) -> "WorkflowBuilder":
        """Add threat intel agent."""
        self.workflow.add_agent(agent, "threat_intel")
        return self

    def with_response_agent(self, agent: BaseAgent) -> "WorkflowBuilder":
        """Add response agent."""
        self.workflow.add_agent(agent, "response")
        return self

    def with_documentation_agent(self, agent: BaseAgent) -> "WorkflowBuilder":
        """Add documentation agent."""
        self.workflow.add_agent(agent, "documentation")
        return self

    def linear_flow(self, *agent_names: str) -> "WorkflowBuilder":
        """Create a linear flow between agents."""
        for i in range(len(agent_names) - 1):
            self.workflow.add_edge(agent_names[i], agent_names[i + 1])
        return self

    def with_supervisor(self, supervisor: BaseAgent) -> "WorkflowBuilder":
        """Add supervisor agent."""
        self.workflow.add_agent(supervisor, "supervisor")
        return self

    def build(self) -> AgentWorkflow:
        """Build the workflow."""
        return self.workflow