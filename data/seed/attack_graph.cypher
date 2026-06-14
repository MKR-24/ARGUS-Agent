MATCH (n) DETACH DELETE n; //Clear existing data

//Create Services
CREATE
    (internet:Node {id: 'internet', name: 'Internet', type: 'external'}),
    (lb:Node {id: 'lb-01', name: 'Load Balancer', type: 'network', version: 'nginx/1.25.3'}),
    (api_gw:Node {id: 'api-gw', name: 'API GATEWAY', type: 'service', version: 'kong/3.6.1', image: 'kong:3.6.1'}),
    (auth:Node {id: 'auth-svc', name: 'Auth Service', type: 'service', version: '2.1.0', image: 'auth:2.1.0', language: 'python'}),
    (user:Node {id: 'user-svc', name: 'User Service', type: 'service', version: '1.8.2', image: 'user:1.8.2', language: 'java'}),
    (order:Node {id: 'order-svc', name: 'Order Service', type: 'service', version:'3.0.1', image:'order:3.0.1', language: 'go'}),
    (payment:Node {id: 'payment-svc', name: 'Payment Service', type: 'service', version: '1.2.0', image: 'payment:1.2.0', language: 'java'}),
    (inventory:Node {id: 'inventory-svc', name: 'Inventory Service', type: 'service', version:'2.4.1', language: 'python'}),
    (notification:Node {id:'notify-svc', name: 'Notification Service', type: 'service', version: '1.0.3', language: 'node'}),
    (report:Node {id: 'report-svc', name:'Reporting Service', type: 'service',version: '1.1.0', language: 'python'}),
    (admin:Node {id: 'admin-svc', name:'Admin Service', type: 'service', version:'0.9.1', language: 'python', internal_only:true}),
    (kafka:Node {id: 'kafka-01', name: 'Kafka Broker', type: 'middleware', version: '3.7.0'}),
    (pg_main:Node {id: 'pg-main', name: 'Postgres Main', type: 'database', version: '16.2'}),
    (pg_order:Node {id: 'pg-order', name: 'Postgres Orders', type: 'database', version: '16.2'}),
    (redis_session:Node {id: 'redis-session', name: 'Redis Session', type: 'cache', version: '7.2.4'}),
    (s3:Node {id: 's3-bucket', name: 'S3 Bucket (reports)', type: 'storage', public_read: false}),
    (vault:Node {id: 'vault-01', name: 'HashiCorp Vault', type: 'secrets', version: '1.16.0'}),
    (prometheus:Node {id: 'prometheus', name: 'Prometheus', type: 'observability'}),
    (grafana:Node {id: 'grafana', name: 'Grafana', type: 'observability', version: '10.4.2'})

// Create Network Paths 
CREATE
    (internet)-[:CONNECTS_TO {port: 443, protocol: 'HTTPS'}]->(lb),
    (lb)-[:CONNECTS_TO {port: 8000, protocol: 'HTTP'}]->(api_gw),
    (api_gw)-[:CONNECTS_TO {port: 8080}]->(auth),
    (api_gw)-[:CONNECTS_TO {port:8081}]->(user),
    (api_gw)-[:CONNECTS_TO {port:8082}]->(order),
    (api_gw)-[:CONNECTS_TO {port: 8083}]->(payment),
    (auth)-[:CONNECTS_TO {port:5432}]->(pg_main),
    (auth)-[:CONNECTS_TO {port: 6379}]->(redis_session),
    (user)-[:CONNECTS_TO {port:5432}]->(pg_main),
    (order)-[:CONNECTS_TO {port:5432}]->(pg_order),
    (order)-[:CONNECTS_TO {port:9092}]->(kafka),
    (payment)-[:CONNECTS_TO {port: 5432}]->(pg_main),
    (payment)-[:CONNECTS_TO {port:8200}]->(vault),
    (inventory)-[:CONNECTS_TO {port: 9092}]->(kafka),
    (inventory)-[:CONNECTS_TO {port:5432}]->(pg_main),
    (notification)-[:CONNECTS_TO {port: 9092}]->(kafka),
    (report)-[:CONNECTS_TO {port: 5432}]->(pg_main),
    (report)-[:CONNECTS_TO {port:443}]->(s3),
    (admin)-[:CONNECTS_TO {port: 5432}]->(pg_main),
    (admin)-[:CONNECTS_TO {port: 8200}]->(vault),
    (kafka)-[:CONNECTS_TO {port: 9092}]->(notification),// Kafka delivers events TO notification (consumer relationship)
    (prometheus)-[:CONNECTS_TO {port:9090}]->(grafana)

//CVE Associations
CREATE
    (log4j_vuln:CVE {id: 'CVE-2021-44228', cvss: 10.0, description:'Log4Shell RCE in Log4j 2.x'}),
    (spring_vuln:CVE {id: 'CVE-2022-22965', cvss: 9.8, description: 'Spring4Shell RCE'}),
    (pg_vuln:CVE {id: 'CVE-2024-0985', cvss: 8.0, description: 'Postgres privilege escalation'})

CREATE
    (user)-[:AFFECTED_BY {package: 'log4j', version: '2.14.1'}]->(log4j_vuln),
    (payment)-[:AFFECTED_BY {package: 'spring-webmvc', version: '5.3.17'}]->(spring_vuln),
    (pg_main)-[:AFFECTED_BY {package: 'postgresql', version: '16.1'}]->(pg_vuln)
;

