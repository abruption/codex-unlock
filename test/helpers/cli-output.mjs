import { once } from "node:events";

export async function collectCliOutput(child) {
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  // Process exit can precede the last pipe data event. Wait for stdio to
  // close before returning captured output; once() also rejects spawn errors.
  const [code, signal] = await once(child, "close");
  return { code, signal, stdout, stderr };
}
