// Safe: filter keys chosen by the code, only values from the request.
app.get("/api/posts", async (req, res) => {
  const id = req.query.id;
  const post = await prisma.post.findUnique({ where: { id: Number(id) } });  // safe: ORM Injection / Filter Leak
  const mine = await prisma.post.findMany({ where: { authorId: req.query.author } });  // safe: ORM Injection / Filter Leak
  res.json(post);
});
