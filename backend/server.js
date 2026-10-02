import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// --- Solución para __dirname con ES Modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Valor especial que representa "sin filtro de sede".
// NUNCA se guarda como sede de un estudiante, sólo se usa al consultar.
const TODAS_SEDES = "TODAS";

// Normaliza lo que llega del cliente: "" / "TODAS" / undefined -> null (sin sede)
function normalizarSede(valor) {
  const s = (valor ?? "").toString().trim();
  if (!s || s.toUpperCase() === TODAS_SEDES) return null;
  return s;
}

// Las sedes se comparan sin distinguir mayúsculas para que "Merced",
// "merced" y "MERCED" no se conviertan en tres sedes distintas.
// Se escapan los comodines de LIKE para que la comparación sea exacta.
function filtroSede(consulta, sede) {
  const patron = sede.replace(/([\\%_*])/g, "\\$1");
  return consulta.ilike("Sede", patron);
}

// --- Variables de entorno obligatorias ---
const REQUIRED_ENV = [
  "SUPABASE_URL",
  "SUPABASE_KEY",
  "JWT_SECRET",
  "ADMIN_USER",
  "ADMIN_PASSWORD_HASH",
];
const faltantes = REQUIRED_ENV.filter((k) => !process.env[k]);
if (faltantes.length) {
  console.error(`❌ ERROR: Faltan variables de entorno: ${faltantes.join(", ")}`);
  process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- Middlewares ---
// CORS restringido: cualquier origen que coincida con el host al que se le
// está pidiendo (mismo origen, sea cual sea el dominio de producción) +
// servidores de desarrollo local típicos (Live Server / similares), que son
// cruzados a propósito (frontend en :5500, backend en :3000).
const origenesDevPermitidos = new Set([
  "http://localhost:5500",
  "http://127.0.0.1:5500",
]);
app.use(
  cors((req, callback) => {
    const origin = req.header("Origin");
    let permitido = true;
    if (origin) {
      let mismoOrigen = false;
      try {
        mismoOrigen = new URL(origin).host === req.headers.host;
      } catch {
        mismoOrigen = false;
      }
      permitido = mismoOrigen || origenesDevPermitidos.has(origin);
    }
    callback(null, { origin: permitido });
  }),
);
app.use(express.json());

// --- Servir el frontend ---
app.use(express.static(path.join(__dirname, "../frontend")));

/* ====================================
   AUTENTICACIÓN (JWT)
==================================== */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Demasiados intentos. Intenta de nuevo más tarde." },
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario || !password) {
      return res.status(400).json({ success: false, error: "Usuario y contraseña requeridos" });
    }

    const esValido =
      usuario === process.env.ADMIN_USER &&
      (await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH));

    if (!esValido) {
      return res.status(401).json({ success: false, error: "Credenciales inválidas" });
    }

    const token = jwt.sign({ usuario }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.json({ success: true, token });
  } catch (err) {
    console.error("❌ Error en login:", err.message);
    res.status(500).json({ success: false, error: "Error interno del servidor" });
  }
});

// Protege las rutas de escritura: exige "Authorization: Bearer <token>"
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Sesión inválida o expirada" });
  }
}

/* ====================================
   1. OBTENER TODOS LOS REGISTROS (público, lo usa la lista de salida)
   Filtro opcional por sede:  /api/codigos?sede=Merced
   Sin el parámetro (o con sede=TODAS) devuelve todas las sedes.
==================================== */
app.get("/api/codigos", async (req, res) => {
  try {
    const sede = normalizarSede(req.query.sede);

    let consulta = supabase
      .from("Codigos")
      .select("*")
      .order("id", { ascending: true });

    // Sede específica -> equivalente a  WHERE Sede = 'Merced'
    if (sede) consulta = filtroSede(consulta, sede);

    const { data, error } = await consulta;

    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error("❌ Error al obtener registros:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   1.b SEDES DISPONIBLES (DINÁMICAS, público)
   Se descubren desde la propia base de datos:
   son los valores distintos de la columna Sede.
   No hay ninguna lista fija en el código.
==================================== */
app.get("/api/sedes", async (req, res) => {
  try {
    const { data, error } = await supabase.from("Codigos").select("Sede");

    if (error) throw error;

    // Valores distintos, agrupando variantes de mayúsculas/minúsculas
    const unicas = new Map();
    for (const r of data) {
      const sede = (r.Sede ?? "").trim();
      if (sede && !unicas.has(sede.toLowerCase())) {
        unicas.set(sede.toLowerCase(), sede);
      }
    }

    const sedes = [...unicas.values()].sort((a, b) => a.localeCompare(b, "es"));

    res.json(sedes);
  } catch (err) {
    console.error("❌ Error al obtener sedes:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   Un mismo código puede repetirse en sedes distintas.
   Lo que NO se permite es el mismo código dos veces
   dentro de la MISMA sede (codigo + sede es único).
==================================== */
async function existeCodigoEnSede(Codigo, sede, ignorarId = null) {
  let consulta = supabase.from("Codigos").select("id").eq("Codigo", Codigo);

  consulta = sede ? filtroSede(consulta, sede) : consulta.is("Sede", null);
  if (ignorarId) consulta = consulta.neq("id", ignorarId);

  const { data, error } = await consulta;
  if (error) throw error;
  return data.length > 0;
}

// Validación mínima de un registro de código (igual a lo que ya exige el formulario)
function validarCodigoPayload(body) {
  const Nombre = (body.Nombre ?? "").toString().trim();
  const Codigo = body.Codigo;
  if (!Nombre) return "El nombre es obligatorio";
  if (Codigo === undefined || Codigo === null || Codigo === "") return "El código es obligatorio";
  return null;
}

/* ====================================
   2. AGREGAR UN NUEVO REGISTRO (requiere sesión admin)
==================================== */
app.post("/api/codigos", requireAuth, async (req, res) => {
  try {
    const errorValidacion = validarCodigoPayload(req.body);
    if (errorValidacion) return res.status(400).json({ error: errorValidacion });

    const { Nombre, Codigo, Docente, Encargado } = req.body;
    const Sede = normalizarSede(req.body.Sede);

    if (await existeCodigoEnSede(Codigo, Sede)) {
      return res.status(409).json({
        error: `El código ${Codigo} ya existe en la sede ${Sede || "(sin sede)"}`,
      });
    }

    const { data, error } = await supabase
      .from("Codigos")
      .insert([{ Nombre, Codigo, Docente, Encargado, Sede }])
      .select();

    if (error) throw error;

    res.json({ success: true, nuevo: data[0] });
  } catch (err) {
    console.error("❌ Error insertando registro:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   3. ACTUALIZAR REGISTRO EXISTENTE (requiere sesión admin)
==================================== */
app.put("/api/codigos/:id", requireAuth, async (req, res) => {
  try {
    const errorValidacion = validarCodigoPayload(req.body);
    if (errorValidacion) return res.status(400).json({ error: errorValidacion });

    const { id } = req.params;
    const { Nombre, Codigo, Docente, Encargado } = req.body;
    const Sede = normalizarSede(req.body.Sede);

    // Verificar que el registro exista
    const { data: existe, error: errorExiste } = await supabase
      .from("Codigos")
      .select("id")
      .eq("id", id);

    if (errorExiste) throw errorExiste;
    if (existe.length === 0) {
      return res.status(404).json({ error: "Registro no encontrado" });
    }

    if (await existeCodigoEnSede(Codigo, Sede, id)) {
      return res.status(409).json({
        error: `El código ${Codigo} ya existe en la sede ${Sede || "(sin sede)"}`,
      });
    }

    const { data, error } = await supabase
      .from("Codigos")
      .update({ Nombre, Codigo, Docente, Encargado, Sede })
      .eq("id", id)
      .select();

    if (error) throw error;

    res.json({ success: true, actualizado: data[0] });
  } catch (err) {
    console.error("❌ Error actualizando registro:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   4. ELIMINAR UN REGISTRO (requiere sesión admin)
==================================== */
app.delete("/api/codigos/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("Codigos")
      .delete()
      .eq("id", id)
      .select();

    if (error) throw error;
    if (data.length === 0) {
      return res.status(404).json({ error: "Registro no encontrado" });
    }

    res.json({ success: true, eliminado: data[0] });
  } catch (err) {
    console.error("❌ Error eliminando registro:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   5. SALIDAS ANTICIPADAS (proxy del formulario de Google)
   Antes el frontend llamaba directo a la API de Google Sheets con una
   API key hardcodeada en el HTML. Ahora el backend hace esa llamada con
   sus propias credenciales y el frontend sólo consume /api/salidas.
==================================== */
let salidasTabCache = null; // nombre de la pestaña, se resuelve una vez por arranque

async function resolverTabSalidas() {
  if (salidasTabCache) return salidasTabCache;

  const { SALIDAS_SHEET_ID, SALIDAS_SHEET_GID, GOOGLE_API_KEY } = process.env;
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${SALIDAS_SHEET_ID}?key=${GOOGLE_API_KEY}`,
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `HTTP ${res.status}`);
  }
  const meta = await res.json();
  const sheet = meta.sheets.find((s) => String(s.properties.sheetId) === SALIDAS_SHEET_GID);
  if (!sheet) throw new Error(`No existe pestaña con gid=${SALIDAS_SHEET_GID}`);

  salidasTabCache = sheet.properties.title;
  return salidasTabCache;
}

app.get("/api/salidas", async (req, res) => {
  try {
    const { SALIDAS_SHEET_ID, GOOGLE_API_KEY } = process.env;
    if (!SALIDAS_SHEET_ID || !GOOGLE_API_KEY) {
      return res.status(500).json({ error: "Salidas anticipadas no está configurado" });
    }

    const tab = await resolverTabSalidas();
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${SALIDAS_SHEET_ID}/values/${encodeURIComponent(tab)}?key=${GOOGLE_API_KEY}`;
    const sheetRes = await fetch(url);
    if (!sheetRes.ok) {
      const err = await sheetRes.json().catch(() => ({}));
      throw new Error(err?.error?.message || `HTTP ${sheetRes.status}`);
    }

    const json = await sheetRes.json();
    const values = json.values || [];
    res.json({ headerRow: values[0] || [], rows: values.slice(1) });
  } catch (err) {
    console.error("❌ Error al obtener salidas:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ====================================
   MANEJO DE RUTAS NO ENCONTRADAS
==================================== */
app.use((req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

/* ====================================
   MANEJO DE ERRORES NO CONTROLADOS
   (p. ej. JSON malformado en el body): responde JSON genérico
   en vez de dejar que Express filtre el stack trace al cliente.
==================================== */
app.use((err, req, res, next) => {
  console.error("❌ Error no controlado:", err.message);
  res.status(500).json({ error: "Error interno del servidor" });
});

/* ====================================
   INICIAR SERVIDOR
==================================== */
app.listen(PORT, () => {
  const url = process.env.VERCEL_URL
    ? `https://${process.env.VERCEL_URL}`
    : `http://localhost:${PORT}`;

  console.log(`🚀 Servidor corriendo en: ${url}`);
});
