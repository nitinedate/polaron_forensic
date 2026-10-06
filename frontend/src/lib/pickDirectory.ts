/** Pick a folder via the File System Access API (avoids Chrome's webkitdirectory upload prompt). */

export interface PickedFolder {
  name: string;
  files: File[];
}

interface DirEntry {
  name: string;
  kind: "file" | "directory";
  getFile(): Promise<File>;
  values(): AsyncIterable<DirEntry>;
}

interface WindowWithDirectoryPicker {
  showDirectoryPicker(): Promise<DirEntry>;
}

async function collectFiles(dir: DirEntry, basePath: string): Promise<File[]> {
  const files: File[] = [];
  for await (const handle of dir.values()) {
    const rel = basePath ? `${basePath}/${handle.name}` : handle.name;
    if (handle.kind === "file") {
      const file = await handle.getFile();
      Object.defineProperty(file, "webkitRelativePath", {
        value: rel,
        configurable: true,
      });
      files.push(file);
    } else {
      files.push(...(await collectFiles(handle, rel)));
    }
  }
  return files;
}

export function supportsDirectoryPicker(): boolean {
  return typeof window !== "undefined" && "showDirectoryPicker" in window;
}

export async function pickDirectory(): Promise<PickedFolder | null> {
  if (!supportsDirectoryPicker()) return null;
  try {
    const dir = await (window as unknown as WindowWithDirectoryPicker).showDirectoryPicker();
    const files = await collectFiles(dir, dir.name);
    return { name: dir.name, files };
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") return null;
    throw err;
  }
}
