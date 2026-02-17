import { useState, useEffect } from "react";
import { analyzeURL } from "../utils/urlAnalyzer";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Pie } from "react-chartjs-2";

ChartJS.register(ArcElement, Tooltip, Legend);

function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [notification, setNotification] = useState("");

  useEffect(() => {
    const saved =
      JSON.parse(localStorage.getItem("scanHistory")) || [];
    setHistory(saved);
  }, []);

  const playSound = () => {
    const audio = new Audio(
      "https://www.soundjay.com/buttons/sounds/button-09.mp3"
    );
    audio.play();
  };

  const handleScan = () => {
    if (!url) return alert("Enter URL");

    setLoading(true);

    setTimeout(() => {
      const analysis = analyzeURL(url);

      const newEntry = {
        url,
        riskLevel: analysis.riskLevel,
        score: analysis.score,
        date: new Date().toLocaleString(),
      };

      const updated = [newEntry, ...history];
      setHistory(updated);
      localStorage.setItem("scanHistory", JSON.stringify(updated));

      playSound();
      setNotification(`Scan Completed: ${analysis.riskLevel} Risk`);

      setTimeout(() => setNotification(""), 3000);

      setLoading(false);
      setUrl("");
    }, 1500);
  };

  const low = history.filter(h => h.riskLevel === "Low").length;
  const medium = history.filter(h => h.riskLevel === "Medium").length;
  const high = history.filter(h => h.riskLevel === "High").length;

  const chartData = {
    labels: ["Low", "Medium", "High"],
    datasets: [
      {
        data: [low, medium, high],
        backgroundColor: ["#22c55e", "#f59e0b", "#ef4444"],
      },
    ],
  };

  return (
    <div>

      {notification && (
        <div className="notification">
          {notification}
        </div>
      )}

      <div className="summary-grid">
        <div className="summary-card"><h3>Total</h3><p>{history.length}</p></div>
        <div className="summary-card green"><h3>Low</h3><p>{low}</p></div>
        <div className="summary-card yellow"><h3>Medium</h3><p>{medium}</p></div>
        <div className="summary-card red"><h3>High</h3><p>{high}</p></div>
      </div>

      <div className="card">
        <h2>URL Scanner</h2>
        <input
          type="text"
          placeholder="Enter URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button onClick={handleScan}>Scan</button>

        {loading && <div className="spinner"></div>}
      </div>

      {history.length > 0 && (
        <div className="card">
          <h2>Risk Analytics</h2>
          <div className="chart-wrapper">
            <Pie data={chartData} />
          </div>
        </div>
      )}
    </div>
  );
}

export default Scanner;