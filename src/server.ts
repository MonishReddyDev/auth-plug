import app from "./app";

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Auth-Plug server running on port ${PORT}`);
});
