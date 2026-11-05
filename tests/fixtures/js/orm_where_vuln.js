// Fixture for orm_where_guard.py (v1.56.0). Mirrors UofTCTF 2025
// "prismatic-blogs": the whole query string becomes a Prisma filter.
app.get("/api/posts", async (req, res) => {
  let query = req.query;
  query.published = true;
  let posts = await prisma.post.findMany({where: query});  // ruleid: ORM Injection / Filter Leak
  const rows = await Post.findAll({ where: req.body });  // ruleid: ORM Injection / Filter Leak
  res.json(posts);
});
