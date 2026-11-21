// Runs the caller in verify.ts from the command line, for the Go test.
//
// Usage: node main.ts <proxy URL> <expected PCR0, hex>
// Prints the signer's GetPubkeyResponse as JSON, or the error on stderr.

import { toJsonString } from "@bufbuild/protobuf";
import { GetPubkeyResponseSchema } from "./gen/signer/v1/service_pb.ts";
import { verifyGetInfo } from "./verify.ts";

const [proxyURL, expectedPCR0] = process.argv.slice(2);
try {
  const response = await verifyGetInfo(proxyURL, expectedPCR0);
  console.log(toJsonString(GetPubkeyResponseSchema, response));
} catch (err) {
  console.error((err as Error).message);
  process.exit(1);
}
