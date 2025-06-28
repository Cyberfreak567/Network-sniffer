import React, { useEffect, useState } from "react";
import axios from "axios";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";
import "./App.css";

const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042", "#AF19FF"];

function App() {
  const [packets, setPackets] = useState([]);
  const [sniffing, setSniffing] = useState(false);

  const startSniffing = async () => {
    try {
      await axios.get("http://localhost:5000/start");
      setSniffing(true);
    } catch (error) {
      console.error("Error starting sniffer:", error.message);
    }
  };

  const stopSniffing = () => {
    setSniffing(false); // Just stops polling; backend will still run unless modified
  };

  const fetchPackets = async () => {
    if (!sniffing) return;
    try {
      const res = await axios.get("http://localhost:5000/packets");
      setPackets(res.data.reverse());
    } catch (error) {
      console.error("Error fetching packets:", error.message);
    }
  };

  useEffect(() => {
    const interval = setInterval(fetchPackets, 2000);
    return () => clearInterval(interval);
  }, [sniffing]);

  const truncate = (text, limit = 100) =>
    text && text.length > limit ? text.substring(0, limit) + "..." : text;

  const getProtocolDistribution = () => {
    const counts = {};
    packets.forEach((pkt) => {
      const protocol = pkt.protocol || "Other";
      counts[protocol] = (counts[protocol] || 0) + 1;
    });

    return Object.entries(counts).map(([protocol, count]) => ({
      name: protocol,
      value: count,
    }));
  };

  return (
    <div className="app-container">
      <div className="overlay" />
      <h2>🌐 Live Packet Sniffer</h2>
      <div style={{ marginBottom: "20px" }}>
        <button onClick={startSniffing} className="btn start">
          Start Sniffing
        </button>
        <button onClick={stopSniffing} className="btn stop">
          Stop Sniffing
        </button>
      </div>

      <div className="dashboard">
        {/* Chart */}
        <div className="chart-container">
          <h3>Protocol Distribution</h3>
          <PieChart width={350} height={300}>
            <Pie
              data={getProtocolDistribution()}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={100}
              fill="#8884d8"
              label
            >
              {getProtocolDistribution().map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={COLORS[index % COLORS.length]}
                />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </div>

        {/* Info */}
        <div className="info-panel">
          <h3>About This Packet Sniffer</h3>
          <p>
            A <strong>Packet Sniffer</strong> captures and analyzes network
            packets in real-time. It provides insight into protocol usage, data
            flow, and communication patterns on a network.
          </p>
          <p>
            Built using <strong>Python (Scapy + Flask)</strong> and{" "}
            <strong>React.js</strong>, this sniffer shows a live feed of
            captured packets with protocol breakdown and basic payload preview.
          </p>
          <p>
            This tool is valuable for network monitoring, cybersecurity
            education, and traffic analysis.
          </p>
        </div>
      </div>

      <h3 style={{ marginTop: "40px" }}>Packet Table</h3>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Length</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt, idx) => (
              <tr key={idx}>
                <td>{pkt.timestamp}</td>
                <td>{pkt.src}</td>
                <td>{pkt.dst}</td>
                <td>{pkt.protocol}</td>
                <td>{pkt.payload}</td>
                <td title={pkt.info}>{truncate(pkt.info)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;
