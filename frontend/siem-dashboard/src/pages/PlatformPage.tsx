export function PlatformPage() {
  const endpoints = [
    { name: "API Gateway", url: "http://localhost:8080/actuator/health" },
    { name: "Kafka UI", url: "http://localhost:8090" },
    { name: "Keycloak", url: "http://localhost:8088" },
    { name: "PostgreSQL", url: "tcp://localhost:5432" },
    { name: "Redis", url: "tcp://localhost:6379" },
    { name: "Kafka (bootstrap)", url: "localhost:29092" }
  ];

  const topics = [
    { topic: "siem.events", producedBy: "ingestion-service (POST /api/events)", consumedBy: "detection-service" },
    { topic: "siem.alerts", producedBy: "detection-service (rules engine)", consumedBy: "alert-service" }
  ];

  return (
    <div className="page-stack">
      <article className="panel">
        <div className="panel-heading">
          <h2>Local Infrastructure</h2>
          <span>docker compose</span>
        </div>
        <div className="data-table">
          <div className="data-row data-head">
            <span>Service</span>
            <span>Endpoint</span>
          </div>
          {endpoints.map((item) => (
            <div className="data-row" key={item.name}>
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
          <span>Phase 3 event backbone</span>
        </div>
        <div className="data-table">
          <div className="data-row data-head">
            <span>Topic</span>
            <span>Produced by</span>
            <span>Consumed by</span>
          </div>
          {topics.map((item) => (
            <div className="data-row" key={item.topic}>
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