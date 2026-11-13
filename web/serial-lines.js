export const MAX_SERIAL_LINE = 4096;

export function createSerialLines(onLine, onError) {
  let pending = "";
  let overflow = false;
  return {
    push(chunk) {
      const text = String(chunk);
      let start = 0;
      while (start < text.length) {
        const end = text.indexOf("\n", start);
        const piece = text.slice(start, end < 0 ? text.length : end);
        if (!overflow) {
          if (pending.length + piece.length > MAX_SERIAL_LINE) {
            pending = "";
            overflow = true;
            onError(`Serial line exceeds ${MAX_SERIAL_LINE} characters`);
          } else pending += piece;
        }
        if (end < 0) break;
        if (!overflow) onLine(pending.replace(/\r$/, ""));
        pending = "";
        overflow = false;
        start = end + 1;
      }
    }
  };
}
