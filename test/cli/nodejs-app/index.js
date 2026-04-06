const http = require("http");

// commit2: uncomment the next line and add lodash to package.json
// const _ = require("lodash");

const port = process.env.ENCLAVE_APP_PORT || 7074;

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok" }));
});

server.listen(port, () => {
  console.log(`listening on :${port}`);
});
