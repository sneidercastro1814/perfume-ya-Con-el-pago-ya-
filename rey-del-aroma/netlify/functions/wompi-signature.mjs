// netlify/functions/wompi-signature.mjs
// Genera la FIRMA DE INTEGRIDAD de Wompi en el servidor.
// El secreto de integridad NUNCA toca el navegador: vive solo en
// la variable de entorno WOMPI_INTEGRITY_SECRET de Netlify.
//
// Firma = SHA256( reference + amountInCents + currency [+ expirationTime] + secret )
// (el orden importa — así lo exige Wompi)

import crypto from "node:crypto";

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };

export default async (req) => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Método no permitido" }), {
      status: 405,
      headers: JSON_HEADERS,
    });
  }

  const secret = process.env.WOMPI_INTEGRITY_SECRET;
  if (!secret) {
    return new Response(
      JSON.stringify({ error: "Falta WOMPI_INTEGRITY_SECRET en el servidor" }),
      { status: 500, headers: JSON_HEADERS }
    );
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "JSON inválido" }), {
      status: 400,
      headers: JSON_HEADERS,
    });
  }

  const reference = String(body?.reference || "").trim();
  const amountInCents = Number(body?.amountInCents);
  const currency = String(body?.currency || "COP").trim();
  const expirationTime = body?.expirationTime
    ? String(body.expirationTime).trim()
    : "";

  // Validaciones básicas: evita firmar basura.
  if (!reference) {
    return new Response(JSON.stringify({ error: "Falta 'reference'" }), {
      status: 400,
      headers: JSON_HEADERS,
    });
  }
  if (!Number.isInteger(amountInCents) || amountInCents <= 0) {
    return new Response(
      JSON.stringify({ error: "'amountInCents' debe ser un entero positivo" }),
      { status: 400, headers: JSON_HEADERS }
    );
  }

  const chain = expirationTime
    ? `${reference}${amountInCents}${currency}${expirationTime}${secret}`
    : `${reference}${amountInCents}${currency}${secret}`;

  const signature = crypto.createHash("sha256").update(chain).digest("hex");

  return new Response(
    JSON.stringify({ signature, reference, amountInCents, currency }),
    { status: 200, headers: JSON_HEADERS }
  );
};

// Ruta limpia: el frontend llama a /api/wompi-signature
export const config = { path: "/api/wompi-signature" };
