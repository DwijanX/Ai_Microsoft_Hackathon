import React, { useState, useEffect, useCallback } from "react";
import { Clock, Server, Activity, AlertTriangle } from "lucide-react";

const styles = `
    .body{
    background-color: #e7e7e7;
    }
  .container {
    width: 100%;
    max-width: 800px;
    margin: 0 auto;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  }

  .header {
    padding: 16px;
    border-bottom: 1px solid #e5e7eb;
  }

  .headerContent {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .title {
    font-size: 1.25rem;
    font-weight: bold;
  }

  .status {
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .status-connected {
    background-color: #dcfce7;
    color: #166534;
  }

  .status-disconnected {
    background-color: #f3f4f6;
    color: #1f2937;
  }

  .status-error {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .contentArea {
    padding: 16px;
    min-height: 400px;
  }

  .errorMessage {
    margin-bottom: 16px;
    padding: 16px;
    background-color: #fee2e2;
    border: 1px solid #fecaca;
    border-radius: 8px;
    color: #dc2626;
  }

  .messageList {
    max-height: 600px;
    min-width: 800px;
    overflow-y: auto;
  }

  .emptyMessage {
    text-align: center;
    color: #6b7280;
    padding: 16px 0;
  }

  /* Network Card Styles */
  .card {
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 16px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);

    color:black
  }

  .card-normal {
    background-color: white;
    border-left: 4px solid #22c55e;
  }

  .card-suspicious {
    background-color: #fef2f2;
    border-left: 4px solid #dc2626;
  }

  .cardHeader {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 16px;
  }

  .categorySection {
    display: flex;
    align-items: center;
  }

  .categoryIcon {
    margin-right: 8px;
  }

  .categoryInfo h3 {
    font-weight: bold;
    margin: 0;
  }

  .decision-normal {
    color: #16a34a;
  }

  .decision-suspicious {
    color: #dc2626;
  }

  .timestamp {
    display: flex;
    align-items: center;
    color: #6b7280;
    font-size: 0.875rem;
  }

  .flowGrid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }

  .flowEndpoint h4 {
    font-size: 0.875rem;
    color: #4b5563;
    font-weight: 600;
    margin-bottom: 4px;
  }

  .endpointInfo {
    display: flex;
    align-items: center;
    font-size: 0.875rem;
  }

  .flowData {
    background-color: #f9fafb;
    border-radius: 4px;
    padding: 8px;
    margin-bottom: 12px;
  }

  .flowDataGrid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    font-size: 0.875rem;
  }

  .flowDataLabel {
    color: #4b5563;
  }

  .payload {
    font-size: 0.875rem;
    color: #4b5563;
    margin-bottom: 12px;
  }

  .reasonsContainer {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .reasonTag {
    font-size: 0.75rem;
    padding: 4px 8px;
    border-radius: 4px;
    display: inline-block;
  }

  .reasonTag-normal {
    background-color: #dcfce7;
    color: #166534;
  }

  .reasonTag-suspicious {
    background-color: #fee2e2;
    color: #991b1b;
  }

  .reconnectButton {
    margin-left: 8px;
    text-decoration: underline;
    cursor: pointer;
  }

  .reconnectButton:hover {
    text-decoration: none;
  }
`;

const NetworkCard = ({ data }) => {
  const isNormal = data.output.decision === "NORMAL";
  if (data?.instruction && data.instruction === "Welcome message") {
    return null;
  }

  return (
    <div className={`card ${isNormal ? "card-normal" : "card-suspicious"}`}>
      <div className="cardHeader">
        <div className="categorySection">
          <span className="categoryIcon">
            {isNormal ? (
              <Activity size={40} color="#22c55e" />
            ) : (
              <AlertTriangle size={40} color="#dc2626" />
            )}
          </span>
          <div className="categoryInfo">
            <h3>{data.output.category}</h3>
            <p className={`decision-${isNormal ? "normal" : "suspicious"}`}>
              {data.output.decision}
            </p>
          </div>
        </div>
        <div className="timestamp">
          <Clock size={16} style={{ marginRight: "4px" }} />
          <span>{new Date(data.input.Timestamp).toLocaleTimeString()}</span>
        </div>
      </div>

      <div className="flowGrid">
        <div className="flowEndpoint">
          <h4>Source</h4>
          <div className="endpointInfo">
            <Server size={16} style={{ marginRight: "4px" }} />
            <span>
              {data.input["Source IP"]}:{data.input["Source Port"]}
            </span>
          </div>
        </div>
        <div className="flowEndpoint">
          <h4>Destination</h4>
          <div className="endpointInfo">
            <Server size={16} style={{ marginRight: "4px" }} />
            <span>
              {data.input["Destination IP"]}:{data.input["Destination Port"]}
            </span>
          </div>
        </div>
      </div>

      <div className="flowData">
        <div className="flowDataGrid">
          <div>
            <span className="flowDataLabel">Protocol: </span>
            <span>{data.input["Flow Data"].protocol}</span>
          </div>
          <div>
            <span className="flowDataLabel">Packets: </span>
            <span>{data.input["Flow Data"].packets}</span>
          </div>
          <div>
            <span className="flowDataLabel">Bytes: </span>
            <span>{data.input["Flow Data"].bytes}</span>
          </div>
        </div>
      </div>

      <div className="payload">
        <span style={{ fontWeight: 500 }}>Payload: </span>
        {data.input.Payload}
      </div>

      <div className="reasonsContainer">
        {data.output.reasons.map((reason, index) => (
          <span
            key={index}
            className={`reasonTag reasonTag-${
              isNormal ? "normal" : "suspicious"
            }`}
          >
            {reason}
          </span>
        ))}
      </div>
    </div>
  );
};

const WebSocketList = () => {
  const [messages, setMessages] = useState([]);
  const [status, setStatus] = useState("disconnected");
  const [error, setError] = useState(null);
  const [ws, setWs] = useState(null);

  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8080");
    setWs(socket);

    return () => {
      if (socket) {
        socket.close();
      }
    };
  }, []);

  useEffect(() => {
    if (!ws) return;

    ws.onopen = () => {
      setStatus("connected");
      setError(null);
    };

    ws.onclose = () => {
      setStatus("disconnected");
    };

    ws.onerror = (error) => {
      setError("WebSocket connection error");
      setStatus("error");
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setMessages((prev) => [...prev, data].slice(-50));
      } catch (err) {
        console.error("Error parsing message:", err);
      }
    };
  }, [ws]);

  const handleReconnect = useCallback(() => {
    if (ws) {
      ws.close();
    }
    const newSocket = new WebSocket("ws://localhost:8080");
    setWs(newSocket);
  }, [ws]);

  return (
    <>
      <style>{styles}</style>
      <div className="container">
        <div className="header">
          <div className="headerContent">
            <h2 className="title">Network Traffic Monitor</h2>
            <span className={`status status-${status}`}>{status}</span>
          </div>
        </div>

        <div className="contentArea">
          {error && (
            <div className="errorMessage">
              {error}
              <button onClick={handleReconnect} className="reconnectButton">
                Try reconnecting
              </button>
            </div>
          )}

          <div className="messageList">
            {messages.length === 0 ? (
              <p className="emptyMessage">
                Waiting for network traffic data...
              </p>
            ) : (
              messages.map((message, index) => (
                <NetworkCard key={index} data={message} />
              ))
            )}
          </div>
        </div>
      </div>
    </>
  );
};

export default WebSocketList;
