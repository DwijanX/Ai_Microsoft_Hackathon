import "./App.css";
import WebSocketList from "./comps/WebSocket";

function App() {
  return (
    <div className="mainCont">
      <div className="list">
        <WebSocketList />
      </div>
      <div className="buttonList">
        <button type="button">Gmail +</button>
        <button type="button">Whatsapp +</button>
        <button type="button">Send Alert +</button>
      </div>
    </div>
  );
}

export default App;
