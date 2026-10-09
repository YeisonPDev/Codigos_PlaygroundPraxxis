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
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_KEY", "JWT_SECRET"];
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

// Login contra la tabla Usuarios de Supabase (antes era un usuario fijo en .env).
// Sólo existen dos roles: "admin" (gestiona Códigos Y Usuarios) y "usuario"
// (gestiona sólo Códigos). La comparación de rol siempre es insensible a
// mayúsculas porque en la tabla está guardado como "Admin"/"Usuario".
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario || !password) {
      return res.status(400).json({ success: false, error: "Usuario y contraseña requeridos" });
    }

    // .eq() es una consulta parametrizada de PostgREST: el valor del usuario
    // nunca se concatena a una cadena SQL, así que no es inyectable.
    const { data, error } = await supabase
      .from("Usuarios")
      .select("id, Nombre, User, Pass, Rol")
      .eq("User", usuario)
      .limit(1);

    if (error) throw error;
    const fila = data[0];

    const esValido = fila && (await bcrypt.compare(password, fila.Pass));
    if (!esValido) {
      return res.status(401).json({ success: false, error: "Credenciales inválidas" });
    }

    const rol = (fila.Rol || "").toLowerCase();
    const token = jwt.sign(
      { id: fila.id, usuario: fila.User, nombre: fila.Nombre, rol },
      process.env.JWT_SECRET,
      { expiresIn: "12h" },
    );
    res.json({ success: true, token, nombre: fila.Nombre, rol });
  } catch (err) {
    console.error("❌ Error en login:", err.message);
    res.status(500).json({ success: false, error: "Error interno del servidor" });
  }
});

// Protege las rutas que requieren sesión: exige "Authorization: Bearer <token>".
// El timeout real de 10 minutos de inactividad lo maneja el frontend (cierra
// la sesión y redirige a login.html); el token en sí dura 12h como techo de
// seguridad por si un token quedara expuesto.
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

// Además de estar logueado, exige un rol concreto (usado para /api/usuarios,
// que sólo el rol "admin" puede gestionar).
function requireRole(rolRequerido) {
  return (req, res, next) => {
    if ((req.usuario?.rol || "") !== rolRequerido) {
      return res.status(403).json({ error: "No tienes permisos para esta acción" });
    }
    next();
  };
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
   4.b ELIMINAR TODOS LOS REGISTROS (requiere sesión + confirmación explícita)
   Exige {"confirmar":"ELIMINAR_TODO"} en el body para no borrar todo
   por un script o un clic accidental.
==================================== */
app.delete("/api/codigos", requireAuth, async (req, res) => {
  try {
    if (req.body?.confirmar !== "ELIMINAR_TODO") {
      return res.status(400).json({ error: "Falta confirmación explícita" });
    }

    // Supabase exige un filtro en los DELETE masivos; "id" siempre es > 0.
    const { data, error } = await supabase.from("Codigos").delete().gt("id", 0).select("id");
    if (error) throw error;

    res.json({ success: true, eliminados: data.length });
  } catch (err) {
    console.error("❌ Error eliminando todos los registros:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   4.c IMPORTAR REGISTROS EN LOTE (CSV / texto pegado, ya parseado por el
   frontend a JSON). Valida y respeta la misma regla de código único por
   sede, fila por fila, para poder reportar exactamente qué se omitió.
==================================== */
app.post("/api/codigos/import", requireAuth, async (req, res) => {
  try {
    const registros = Array.isArray(req.body?.registros) ? req.body.registros : null;
    if (!registros || registros.length === 0) {
      return res.status(400).json({ error: "No se recibieron registros para importar" });
    }
    if (registros.length > 2000) {
      return res.status(400).json({ error: "Demasiados registros en un solo lote (máx. 2000)" });
    }

    const insertados = [];
    const omitidos = [];

    for (let i = 0; i < registros.length; i++) {
      const fila = registros[i] || {};
      const numFila = i + 1;

      const errorValidacion = validarCodigoPayload(fila);
      if (errorValidacion) {
        omitidos.push({ fila: numFila, motivo: errorValidacion });
        continue;
      }

      const Nombre = fila.Nombre.toString().trim();
      const Codigo = fila.Codigo;
      const Docente = fila.Docente || "";
      const Encargado = fila.Encargado || "";
      const Sede = normalizarSede(fila.Sede);

      try {
        if (await existeCodigoEnSede(Codigo, Sede)) {
          omitidos.push({ fila: numFila, motivo: `Código ${Codigo} ya existe en esa sede` });
          continue;
        }

        const { error } = await supabase
          .from("Codigos")
          .insert([{ Nombre, Codigo, Docente, Encargado, Sede }]);

        if (error) throw error;
        insertados.push(numFila);
      } catch (err) {
        omitidos.push({ fila: numFila, motivo: err.message });
      }
    }

    res.json({ success: true, insertados: insertados.length, omitidos });
  } catch (err) {
    console.error("❌ Error importando registros:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ====================================
   USUARIOS DEL SISTEMA (sólo rol "admin")
   Dos roles posibles: "admin" (ve Códigos + Usuarios) y "usuario" (sólo
   Códigos). Las contraseñas siempre se guardan con bcrypt, nunca en texto
   plano, y nunca se devuelven en las respuestas.
==================================== */
function validarUsuarioPayload(body, { exigirPass }) {
  const Nombre = (body.Nombre ?? "").toString().trim();
  const User = (body.User ?? "").toString().trim();
  const Rol = (body.Rol ?? "").toString().trim().toLowerCase();

  if (!Nombre) return "El nombre es obligatorio";
  if (!User) return "El usuario (login) es obligatorio";
  if (Rol !== "admin" && Rol !== "usuario") return 'El rol debe ser "admin" o "usuario"';
  if (exigirPass && !(body.Pass ?? "").toString().trim()) return "La contraseña es obligatoria";
  return null;
}

// La tabla guarda el rol como "Admin"/"Usuario"; esto normaliza cualquier
// variante de mayúsculas que llegue del formulario a ese mismo formato.
function capitalizar(valor) {
  const limpio = (valor || "").toString().trim().toLowerCase();
  return limpio.charAt(0).toUpperCase() + limpio.slice(1);
}

// Nunca se expone la columna Pass al frontend.
const SELECT_USUARIO_SEGURO = "id, Nombre, Tipodoc, Numdoc, User, Rol";

app.get("/api/usuarios", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("Usuarios")
      .select(SELECT_USUARIO_SEGURO)
      .order("id", { ascending: true });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("❌ Error al obtener usuarios:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.post("/api/usuarios", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const errorValidacion = validarUsuarioPayload(req.body, { exigirPass: true });
    if (errorValidacion) return res.status(400).json({ error: errorValidacion });

    const { Nombre, Tipodoc, User, Pass, Rol } = req.body;
    const Numdoc = req.body.Numdoc ? Number(req.body.Numdoc) : null;

    const { data: existe, error: errorExiste } = await supabase
      .from("Usuarios")
      .select("id")
      .eq("User", User);
    if (errorExiste) throw errorExiste;
    if (existe.length > 0) {
      return res.status(409).json({ error: `El usuario "${User}" ya existe` });
    }

    const hash = await bcrypt.hash(Pass, 10);
    const { data, error } = await supabase
      .from("Usuarios")
      .insert([{ Nombre, Tipodoc, Numdoc, User, Pass: hash, Rol: capitalizar(Rol) }])
      .select(SELECT_USUARIO_SEGURO);

    if (error) throw error;
    res.json({ success: true, nuevo: data[0] });
  } catch (err) {
    console.error("❌ Error creando usuario:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.put("/api/usuarios/:id", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const errorValidacion = validarUsuarioPayload(req.body, { exigirPass: false });
    if (errorValidacion) return res.status(400).json({ error: errorValidacion });

    const { id } = req.params;
    const { Nombre, Tipodoc, User, Pass, Rol } = req.body;
    const Numdoc = req.body.Numdoc ? Number(req.body.Numdoc) : null;

    const { data: existe, error: errorExiste } = await supabase
      .from("Usuarios")
      .select("id, Rol")
      .eq("id", id);
    if (errorExiste) throw errorExiste;
    if (existe.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });

    const { data: duplicado, error: errorDup } = await supabase
      .from("Usuarios")
      .select("id")
      .eq("User", User)
      .neq("id", id);
    if (errorDup) throw errorDup;
    if (duplicado.length > 0) {
      return res.status(409).json({ error: `El usuario "${User}" ya existe` });
    }

    // Nunca dejar el sistema sin ningún administrador (p. ej. al cambiarse
    // uno mismo el rol por error).
    const eraAdmin = (existe[0].Rol || "").toLowerCase() === "admin";
    const seraAdmin = (Rol || "").toLowerCase() === "admin";
    if (eraAdmin && !seraAdmin) {
      const { data: admins, error: errorAdmins } = await supabase
        .from("Usuarios")
        .select("id")
        .ilike("Rol", "admin");
      if (errorAdmins) throw errorAdmins;
      if (admins.length <= 1) {
        return res.status(409).json({ error: "No puedes quitarle el rol admin al único administrador" });
      }
    }

    const cambios = { Nombre, Tipodoc, Numdoc, User, Rol: capitalizar(Rol) };
    if ((Pass ?? "").toString().trim()) {
      cambios.Pass = await bcrypt.hash(Pass, 10);
    }

    const { data, error } = await supabase
      .from("Usuarios")
      .update(cambios)
      .eq("id", id)
      .select(SELECT_USUARIO_SEGURO);

    if (error) throw error;
    res.json({ success: true, actualizado: data[0] });
  } catch (err) {
    console.error("❌ Error actualizando usuario:", err.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.delete("/api/usuarios/:id", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const { id } = req.params;

    const { data: objetivo, error: errorObjetivo } = await supabase
      .from("Usuarios")
      .select("id, Rol")
      .eq("id", id);
    if (errorObjetivo) throw errorObjetivo;
    if (objetivo.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });

    // Nunca dejar el sistema sin ningún administrador.
    if ((objetivo[0].Rol || "").toLowerCase() === "admin") {
      const { data: admins, error: errorAdmins } = await supabase
        .from("Usuarios")
        .select("id")
        .ilike("Rol", "admin");
      if (errorAdmins) throw errorAdmins;
      if (admins.length <= 1) {
        return res.status(409).json({ error: "No puedes eliminar al único administrador" });
      }
    }

    const { data, error } = await supabase
      .from("Usuarios")
      .delete()
      .eq("id", id)
      .select(SELECT_USUARIO_SEGURO);

    if (error) throw error;
    res.json({ success: true, eliminado: data[0] });
  } catch (err) {
    console.error("❌ Error eliminando usuario:", err.message);
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
