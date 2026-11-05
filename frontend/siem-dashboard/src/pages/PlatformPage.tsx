export function PlatformPage() {
  const endpoints = [
    { name: "API Gateway", url: "http://localhost:18080/actuator/health" },
    { name: "Kafka UI (--profile tools)", url: "http://localhost:18090" },
    { name: "Keycloak", url: "http://localhost:18088" },
    { name: "Grafana", url: "http://localhost:13000" },
    { name: "PostgreSQL", url: "tcp://localhost:15432" },
    { name: "Redis", url: "tcp://localhost:16379" },
    { name: "Kafka (bootstrap)", url: "localhost:19092" }
  ];

  const topics = [
    { topic: "siem.events", producedBy: "ingestion-service", consumedBy: "detection-service, search-service" },
    { topic: "siem.alerts", producedBy: "detection-service (rules engine)", consumedBy: "alert-service, incident-service, search-service" },
    { topic: "siem.incidents", producedBy: "incident-service (correlation)", consumedBy: "downstream integrations" },
    { topic: "siem.rules", producedBy: "detection-service (rule API)", consumedBy: "every detection-service instance" }
  ];

  return (
    <div className="page-stack">
      <article className="panel">
        <div className="panel-heading">
          <h2>Local Infrastructure</h2>
          <span>docker compose</span>
        </div>
        <div className="data-table">
          <div className="data-row data-head endpoint-grid">
            <span>Service</span>
            <span>Endpoint</span>
          </div>
          {endpoints.map((item) => (
            <div className="data-row endpoint-grid" key={item.name}>
              <span>
                <strong>{item.name}</strong>
              </span>
              <span>
                <code>{item.url}</code>
              </span>
            </div>
          ))}
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading">
          <h2>Kafka Topics</h2>
          <span>event backbone</span>
        </div>
        <div className="data-table">
          <div className="data-row data-head topic-grid">
            <span>Topic</span>
            <span>Produced by</span>
            <span>Consumed by</span>
          </div>
          {topics.map((item) => (
            <div className="data-row topic-grid" key={item.topic}>
              <span>
                <code>{item.topic}</code>
              </span>
              <span>{item.producedBy}</span>
              <span>{item.consumedBy}</span>
            </div>
          ))}
        </div>
      </article>
    </div>
  );
}