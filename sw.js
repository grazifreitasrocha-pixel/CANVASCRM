// Service worker simples: deixa o "casco" do app (o próprio index.html) disponível
// mesmo sem internet, pra abrir instantâneo. Os dados (API) sempre buscam da rede --
// isso aqui só evita a tela branca quando o sinal cai.
const CACHE_NAME = "canvas-crm-shell-v1";
const SHELL_FILES = ["/", "/index.html", "/manifest.json", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const { request } = event;

  // Nunca guarda em cache chamadas de API -- essas sempre precisam ser buscadas na hora.
  if (request.url.includes("/api/")) return;

  // Para navegação (abrir o app), tenta a rede primeiro; se falhar (sem sinal), usa o cache.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() => caches.match("/index.html"))
    );
    return;
  }

  // Para os demais arquivos estáticos (ícones, manifest), cache primeiro, rede como reforço.
  event.respondWith(
    caches.match(request).then((cached) => cached || fetch(request))
  );
});
