# Route map and local AI

Open examples/route-map.html in a browser for an interactive example. Its synthetic orders route gives one Service a weight of 90 and the canary Service a weight of 10. Select a resource with the mouse, keyboard or dropdown. Incoming and outgoing paths stay highlighted, and the detail pane shows each backend reference's port and weight. A rule's detail includes its match expressions.

## Use your cluster

```sh
setura --context edge map -n apps > routes.html
setura --context edge snapshot -n apps > snapshot.json
setura map --snapshot snapshot.json --format json > graph.json
setura impact Service/apps/orders --snapshot snapshot.json > impact.json
```

Map reads Gateway and HTTPRoute specs in one namespace, or renders a saved snapshot entirely offline. The HTML contains its scripts and data. Referenced external parents and backends can appear without a declaration in this namespace. Parent references without a listener name connect to the Gateway. The detail pane preserves parent port restrictions. Impact walks declared references upstream and excludes zero-weight backends. Request mirrors and runtime policy decisions are outside this graph. A relationship alone does not establish attachment, reachability or actual traffic. Resource names, hostnames and match values are embedded in the export.

## Ask a question

```sh
setura explain https://orders.example.test/checkout --json > probe.json
setura ai probe.json
setura ai probe.json --model YOUR_INSTALLED_MODEL --ask "What failed first and what observation would distinguish likely causes?"
setura ai graph.json --model YOUR_INSTALLED_MODEL --ask "Which Services receive checkout traffic according to this configuration?"
setura ai impact.json --model YOUR_INSTALLED_MODEL --ask "Which routes should we verify before retiring this Service?"
```

Use the exact model name from your local Ollama installation. Start Ollama before requesting inference. Setura sends the question and extracted facts to the local chat API on 127.0.0.1:11434; use --port for a different local port. Choose a locally installed model that supports structured outputs. Model selection and downloads are managed by Ollama. [Ollama chat API](https://docs.ollama.com/api/chat) · [Structured outputs](https://docs.ollama.com/capabilities/structured-outputs)

Without --model the response is a deterministic evidence summary, including suggested checks for known probe failures. With --model each interpretation must cite one or more existing evidence IDs. The validator checks references and response shape. The operator evaluates whether the interpretation follows from those facts. The model has no tools or command runner. A stopped server, invalid model response or invented ID produces a CLI error. Use the evidence-only command to inspect observations independently.

Accepted report inputs are explain --json, check, compare, gate, inspect, map --format json and impact. Gate analysis uses the final sample and overall outcome. For large topologies, use an impact report to narrow the question.
