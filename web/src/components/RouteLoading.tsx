export function RouteLoading() {
  return (
    <main className="am-route-loading" aria-busy="true" aria-live="polite">
      <span className="am-spinner" aria-hidden="true" />
      <p>Loading interface</p>
    </main>
  );
}
