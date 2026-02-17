import { useState, useEffect } from "react";
import { analyzeURL } from "../utils/urlAnalyzer";
import { Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(ArcElement, Tooltip, Legend);

function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("scanHistory")) || [];
      if (Array.isArray(saved)) {
        setHistory(saved);
      } else {
        setHistory([]);
      }
    } catch (e) {
      console.error("Failed to parse history", e);
      setHistory([]);
    }
  }, []);

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

      setLoading(false);
      setUrl("");
    }, 1200);
  };

  const low = history.filter(h => h.riskLevel === "Low").length;
  const medium = history.filter(h => h.riskLevel === "Medium").length;
  const high = history.filter(h => h.riskLevel === "High").length;

  // Calculate Risk Score (0-100) based on High/Medium threats found
  const totalScans = history.length;
  const riskScore = totalScans === 0 ? 0 : Math.round(((high * 10) + (medium * 5)) / totalScans * 10);
  const normalizedRisk = Math.min(riskScore, 100);

  const chartData = {
    labels: ["Low", "Medium", "High"],
    datasets: [
      {
        data: [low, medium, high],
        backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
        borderColor: "rgba(255,255,255,0.1)",
        borderWidth: 2,
      },
    ],
  };

  return (
    <div>

      <div className="chart-stats-grid">
        <div className="stat-card"><h3>{history.length}</h3><p>Total Scans</p></div>
        <div className="stat-card safe"><h3>{low}</h3><p>Low Risk</p></div>
        <div className="stat-card warning"><h3>{medium}</h3><p>Medium Risk</p></div>
        <div className="stat-card danger"><h3>{high}</h3><p>High Risk</p></div>
      </div>

      <div className="card">
        <h2>URL Scanner</h2>
        <div className="scan-row">
          <input
            type="text"
            className={loading ? "animate-pulse" : ""}
            placeholder="Enter suspicious URL..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button className="primary-btn" onClick={handleScan}>Scan Target</button>
        </div>

        {loading && <div className="spinner"></div>}
      </div>

      {history.length > 0 && (
        <div className="card">
          <h2>Risk Analytics</h2>

          <div className="flex-center" style={{ gap: '3rem', flexWrap: 'wrap' }}>
            <div className="chart-wrapper small" style={{ width: '240px' }}>
              <Pie data={chartData} />
            </div>

            <div className={`risk-card-container ${normalizedRisk > 50 ? 'animate-pulse' : ''}`} style={{ padding: '2rem', borderRadius: '12px', minWidth: '220px' }}>
              <div className="risk-score brand-glitch" style={{ fontSize: '3.5rem', fontWeight: 'bold', color: normalizedRisk > 70 ? '#ef4444' : '#10b981' }}>
                {normalizedRisk}%
              </div>
              <div className="risk-label" style={{ color: '#94a3b8', letterSpacing: '2px', textTransform: 'uppercase' }}>Current Risk</div>
            </div>
          </div>

        </div>
      )}

    </div>
  );
}

export default Scanner;