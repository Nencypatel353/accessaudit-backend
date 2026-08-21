"""
Tracks active WebSocket connections per scan job and broadcasts
progress messages to whichever frontend client is listening.
"""
from fastapi import WebSocket
from typing import Dict, List


class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, job_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(job_id, []).append(websocket)

    def disconnect(self, job_id: str, websocket: WebSocket):
        if job_id in self.active_connections:
            if websocket in self.active_connections[job_id]:
                self.active_connections[job_id].remove(websocket)
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]

    async def send_progress(self, job_id: str, status: str, message: str):
        if job_id not in self.active_connections:
            return
        payload = {"job_id": job_id, "status": status, "message": message}
        dead_sockets = []
        for ws in self.active_connections[job_id]:
            try:
                await ws.send_json(payload)
            except Exception:
                dead_sockets.append(ws)
        for ws in dead_sockets:
            self.disconnect(job_id, ws)


manager = WebSocketManager()
