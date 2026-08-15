export function RouteLoading({
  message = "Loading interface",
}: {
  message?: string;
}) {
  return (
    <main className="am-route-loading" aria-busy="true" aria-live="polite">
      <span className="am-spinner" aria-hidden="true" />
      <p>{message}</p>
    </main>
  );
}
