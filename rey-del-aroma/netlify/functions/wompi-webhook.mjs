// netlify/functions/wompi-webhook.mjs
// Recibe los EVENTOS de Wompi (transaction.updated) y valida que de verdad
// vengan de Wompi usando el secreto de eventos (WOMPI_EVENTS_SECRET).
//
// Validación (según Wompi): se concatenan los valores de las propiedades
// listadas en signature.properties (en orden), luego el timestamp del evento,
// luego el secreto de eventos. Se aplica SHA256 y debe coincidir con
// signature.checksum (en hex).
//
// Aquí solo validamos y registramos. Cuando tengas base de datos / correo,
// este es el lugar correcto para marcar el pedido como PAGADO de forma segura
// (nunca confíes solo en el redirect del navegador para confirmar el pago).

import crypto from "node:crypto";

// Resuelve una ruta tipo "transaction.amount_in_cents" dentro de un objeto.
function getPath(obj, path) {
  return path.split(".").reduce((acc, key) => (acc == null ? acc : acc[key]), obj);
}

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Método no permitido", { status: 405 });
  }

  const secret = process.env.WOMPI_EVENTS_SECRET;
  if (!secret) return new Response("Falta WOMPI_EVENTS_SECRET", { status: 500 });

  let event;
  try {
    event = await req.json();
  } catch {
    return new Response("JSON inválido", { status: 400 });
  }

  const properties = event?.signature?.properties || [];
  const checksumRecibido = String(event?.signature?.checksum || "");
  const timestamp = event?.timestamp ?? "";

  // Concatena los valores de las propiedades firmadas.
  let chain = "";
  for (const prop of properties) {
    chain += String(getPath(event?.data, prop) ?? "");
  }
  chain += String(timestamp) + secret;

  const calculado = crypto.createHash("sha256").update(chain).digest("hex");

  const ok =
    checksumRecibido.length === calculado.length &&
    crypto.timingSafeEqual(
      Buffer.from(checksumRecibido.toLowerCase()),
      Buffer.from(calculado.toLowerCase())
    );

  if (!ok) {
    return new Response("Firma inválida", { status: 401 });
  }

  // ✅ Evento legítimo de Wompi.
  const tx = event?.data?.transaction || {};
  // Los logs aparecen en Netlify → Functions → wompi-webhook.
  console.log("Wompi evento válido:", {
    referencia: tx.reference,
    estado: tx.status, // APPROVED | DECLINED | VOIDED | ERROR
    montoCentavos: tx.amount_in_cents,
    id: tx.id,
  });

  // TODO (cuando tengas backend/BD): si tx.status === "APPROVED",
  // marca el pedido como pagado, envía correo de confirmación, etc.

  return new Response("ok", { status: 200 });
};

export const config = { path: "/api/wompi-webhook" };
