export const CONFIG_OFFSET = 0x290000;
const PARTS = ["bootloader.bin", "partitions.bin", "firmware.bin"];

export function buildInstallManifest(base, manifestUrl, board, configUrl) {
  if (!base || !Array.isArray(base.builds) || base.builds.length !== 1)
    throw new Error("Expected one firmware build");
  const build = base.builds[0];
  const chipFamily = board === "lilygo-t-dongle-c5" ? "ESP32-C5" : "ESP32";
  const bootOffset = chipFamily === "ESP32-C5" ? 0x2000 : 0x1000;
  const offsets = [bootOffset, 0x8000, 0x10000];
  if (build.chipFamily !== chipFamily || !Array.isArray(build.parts) || build.parts.length !== 3)
    throw new Error("Firmware manifest does not match the selected board");
  const parts = build.parts.map((part, index) => {
    const url = new URL(part.path, manifestUrl);
    if (part.offset !== offsets[index] || url.pathname.split("/").slice(-3).join("/") !==
        `firmware/${board}/${PARTS[index]}` || url.origin !== new URL(manifestUrl).origin)
      throw new Error("Firmware path or offset does not match the selected board");
    return { path: url.href, offset: part.offset };
  });
  if (!configUrl.startsWith("blob:")) throw new Error("Missing configuration image");
  parts.push({ path: configUrl, offset: CONFIG_OFFSET });
  return { ...base, builds: [{ ...build, parts }] };
}
