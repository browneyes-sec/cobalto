"""
MCP Transport Layer - SSE (Server-Sent Events) transport for HTTP.
"""

import json
import asyncio
import logging
from typing import Any, AsyncGenerator, Callable, Dict, Optional
from datetime import datetime

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from cobalto.mcp.server import MCPServer
from cobalto.mcp.protocol import JSONRPCRequest

logger = logging.getLogger(__name__)


class SSETransport:
    """
    SSE Transport for MCP protocol.

    Provides:
    - POST /messages - Receive JSON-RPC messages
    - GET /sse - SSE stream for server-to-client messages
    """

    def __init__(
        self,
        server: MCPServer,
        host: str = "0.0.0.0",
        port: int = 8002,
        cors_origins: Optional[list] = None,
    ):
        self.server = server
        self.host = host
        self.port = port
        self.cors_origins = cors_origins or ["*"]

        # Session management
        self._sessions: Dict[str, asyncio.Queue] = {}
        self._session_counter = 0

        # Build Starlette app
        self.app = self._build_app()

    def _build_app(self) -> Starlette:
        """Build Starlette ASGI application."""
        routes = [
            Route("/sse", self._handle_sse, methods=["GET"]),
            Route("/messages", self._handle_message, methods=["POST"]),
            Route("/", self._handle_index, methods=["GET"]),
            Route("/health", self._handle_health, methods=["GET"]),
        ]

        middleware = [
            Middleware(
                CORSMiddleware,
                allow_origins=self.cors_origins,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        ]

        return Starlette(
            routes=routes,
            middleware=middleware,
            on_startup=[self._on_startup],
            on_shutdown=[self._on_shutdown],
        )

    async def _on_startup(self) -> None:
        """Handle server startup."""
        logger.info(f"MCP SSE Transport starting on {self.host}:{self.port}")

    async def _on_shutdown(self) -> None:
        """Handle server shutdown."""
        logger.info("MCP SSE Transport shutting down")
        # Close all sessions
        for session_id, queue in self._sessions.items():
            await queue.put(None)  # Signal to close

    async def _handle_sse(self, request: Request) -> HTMLResponse:
        """Handle SSE connection."""
        session_id = self._create_session()
        queue: asyncio.Queue = asyncio.Queue()
        self._sessions[session_id] = queue

        async def event_generator() -> AsyncGenerator[str, None]:
            try:
                # Send initial connection event
                yield f"event: connected\ndata: {json.dumps({'session_id': session_id})}\n\n"

                while True:
                    try:
                        message = await asyncio.wait_for(queue.get(), timeout=30)
                        if message is None:
                            break
                        yield f"data: {json.dumps(message)}\n\n"
                    except asyncio.TimeoutError:
                        # Send keepalive
                        yield ": keepalive\n\n"

            finally:
                # Cleanup
                self._sessions.pop(session_id, None)

        return HTMLResponse(
            content="",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
            status_code=200,
            background=self._stream_events(event_generator()),
        )

    async def _stream_events(self, generator: AsyncGenerator) -> None:
        """Background task to stream events."""
        # This is handled by Starlette's background task system
        pass

    async def _handle_message(self, request: Request) -> JSONResponse:
        """Handle incoming JSON-RPC message."""
        try:
            body = await request.json()
            session_id = request.query_params.get("session_id")

            # Process message
            response = await self.server.handle_message(body)

            # Send response to SSE stream if session exists
            if session_id and session_id in self._sessions:
                if response:
                    await self._sessions[session_id].put(json.loads(response))

            return JSONResponse(
                content=json.loads(response) if response else {"ok": True},
                status_code=200,
            )

        except Exception as e:
            logger.exception(f"Error handling message: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": str(e)},
                    "id": None,
                },
                status_code=500,
            )

    async def _handle_index(self, request: Request) -> HTMLResponse:
        """Handle index page with MCP Inspector."""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Cobalto MCP Server</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #1a1a2e; }
        .status { padding: 10px; background: #e8f5e9; border-radius: 4px; margin: 10px 0; }
        .endpoint { background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 5px 0; font-family: monospace; }
        code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Cobalto MCP Server</h1>
    <div class="status">Status: Running</div>
    <h2>Endpoints</h2>
    <div class="endpoint">GET /sse - SSE stream for server-to-client messages</div>
    <div class="endpoint">POST /messages - Send JSON-RPC messages to server</div>
    <h2>Protocol</h2>
    <p>JSON-RPC 2.0 over SSE transport</p>
    <h2>Server Info</h2>
    <pre id="server-info">Loading...</pre>
    <script>
        fetch('/health').then(r => r.json()).then(data => {
            document.getElementById('server-info').textContent = JSON.stringify(data, null, 2);
        });
    </script>
</body>
</html>
"""
        return HTMLResponse(content=html)

    async def _handle_health(self, request: Request) -> JSONResponse:
        """Handle health check."""
        return JSONResponse(
            content={
                "status": "healthy",
                "server": self.server.get_server_info(),
                "sessions": len(self._sessions),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    def _create_session(self) -> str:
        """Create a new session ID."""
        self._session_counter += 1
        return f"session-{self._session_counter}"

    async def run(self) -> None:
        """Run the SSE transport server."""
        import uvicorn

        config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="info",
        )
        server = uvicorn.Server(config)
        await server.serve()


class StdioTransport:
    """
    Stdio Transport for MCP protocol.

    Reads JSON-RPC messages from stdin and writes to stdout.
    Useful for CLI tools and local integrations.
    """

    def __init__(self, server: MCPServer):
        self.server = server
        self._running = False

    async def run(self) -> None:
        """Run the stdio transport."""
        self._running = True
        logger.info("MCP Stdio Transport starting")

        try:
            while self._running:
                try:
                    # Read line from stdin
                    line = await asyncio.get_event_loop().run_in_executor(
                        None, input
                    )

                    if not line.strip():
                        continue

                    # Handle message
                    response = await self.server.handle_message(line)

                    # Write response to stdout
                    if response:
                        print(response, flush=True)

                except EOFError:
                    break
                except KeyboardInterrupt:
                    break

        finally:
            self._running = False
            logger.info("MCP Stdio Transport stopped")

    def stop(self) -> None:
        """Stop the transport."""
        self._running = False
