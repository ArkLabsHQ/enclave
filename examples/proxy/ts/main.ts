// Runs the caller in verify.ts from the command line, for the Go test.
//
// Usage: node main.ts <grpc|rest> <proxy URL> <expected PCR0, hex>
// Prints the signer's GetPubkeyResponse as JSON, or the error on stderr.

import { toJsonString } from "@bufbuild/protobuf";
import { GetPubkeyResponseSchema } from "./gen/signer/v1/service_pb.ts";
import { verifyGetInfo, verifyGetInfoREST } from "./verify.ts";

// The caller for each way the proxy calls the signer.
const verifiers = { grpc: verifyGetInfo, rest: verifyGetInfoREST };

const [call, proxyURL, expectedPCR0] = process.argv.slice(2);
try {
  const verify = verifiers[call as keyof typeof verifiers];
  if (!verify) {
    throw new Error(`unknown call ${call}: want grpc or rest`);
  }
  const response = await verify(proxyURL, expectedPCR0);
  console.log(toJsonString(GetPubkeyResponseSchema, response));
} catch (err) {
  console.error((err as Error).message);
  process.exit(1);
}
