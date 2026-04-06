const http = require("http");
const _ = require("lodash");

const port = process.env.ENCLAVE_APP_PORT || 7074;

const server = http.createServer((req, res) => {
  const body = { status: "ok", message: _.capitalize("hello enclave") };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
});

server.listen(port, () => {
  console.log(`listening on :${port}`);
});
