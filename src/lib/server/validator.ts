/**
 * Validación y sanitización estricta de inputs de escaneo (IoCs).
 */

export interface ValidationResult {
  valid: boolean;
  sanitized: string;
  error?: string;
}

export function validateIndicator(input: unknown): ValidationResult {
  if (typeof input !== "string") {
    return { valid: false, sanitized: "", error: "El indicador debe ser una cadena de texto." };
  }

  // Límite de longitud preventiva contra DoS de memoria
  const trimmed = input.trim().slice(0, 2048);

  if (!trimmed) {
    return { valid: false, sanitized: "", error: "El indicador no puede estar vacío." };
  }

  // Eliminar caracteres de control y secuencias zero-width / bidirectional overrides
  const sanitized = trimmed.replace(
    /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u202A-\u202E\uFEFF]/g,
    ""
  );

  // Bloqueo explícito de inyección HTML/Script
  if (/<[^>]+>/i.test(sanitized)) {
    return { valid: false, sanitized: "", error: "Entrada inválida: No se permite contenido HTML o scripts." };
  }

  // No permitir protocolos peligrosos como file://, javascript:, data:
  if (/^(file|javascript|data|vbscript):/i.test(sanitized)) {
    return { valid: false, sanitized: "", error: "Protocolo no permitido por seguridad." };
  }

  return { valid: true, sanitized };
}
