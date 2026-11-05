// Safe counterparts: stored request data returned as JSON, and an HTML
// response built from a Map that only ever holds server-generated values.
const lists = new Map();
const banners = new Map();
banners.set("home", "<b>Welcome</b>");

app.post("/list", (req, res) => {
  const items = req.body.items;
  lists.set(req.body.id, items);
});

app.get("/list/:id", (req, res) => {
  res.json(lists.get(req.params.id));
  res.send(lists.get(req.params.id));  // safe: Cross-Site Scripting (XSS)
});

app.get("/", (req, res) => {
  res.type("text/html").send(banners.get("home"));  // safe: Cross-Site Scripting (XSS)
});
