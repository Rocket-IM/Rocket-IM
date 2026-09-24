const parameters = new URL(location.href).searchParams;
if (["interop_url", "interop_run_id", "interop_endpoint_id"].some(name => parameters.has(name))) {
  const { runInterop } = await import("./interop.js");
  await runInterop();
} else {
  await import("./consumer.js");
}
export {};
