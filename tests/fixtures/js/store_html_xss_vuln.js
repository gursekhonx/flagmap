// Fixture for store_html_xss_guard.py (v1.48.0). Mirrors LA CTF 2023
// "california-state-police" and "metaverse": request data stored in a Map
// on one route, served raw as HTML on another.
const reports = new Map();
const posts = new Map();

app.post("/report", (req, res) => {
  const crime = req.body.crime;
  reports.set(uuid(), crime);
});

app.post("/post", (req, res) => {
  const { content } = req.body;
  posts.set(uuid(), content);
});

app.get("/report/:id", (req, res) => {
  res.type("text/html").send(reports.get(req.params.id));  // ruleid: Cross-Site Scripting (XSS)
});

app.get("/post/:id", (req, res) => {
  res.type("text/html");
  res.send(template.replace("$CONTENT", () => posts.get(req.params.id)));  // ruleid: Cross-Site Scripting (XSS)
});
