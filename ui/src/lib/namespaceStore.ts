import { create } from "zustand";
import { KAGENT_SELECTED_NAMESPACE_COOKIE } from "@/lib/namespaceConstants";

function getCookieValue(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  const parts = document.cookie.split(";").map((p) => p.trim());
  for (const part of parts) {
    if (part.startsWith(`${name}=`)) {
      return decodeURIComponent(part.substring(name.length + 1));
    }
  }
  return undefined;
}

function setCookieValue(name: string, value: string) {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; SameSite=Lax`;
}

interface NamespaceStore {
  selectedNamespace: string;
  setSelectedNamespace: (ns: string) => void;
}

export const useNamespaceStore = create<NamespaceStore>((set) => ({
  selectedNamespace: getCookieValue(KAGENT_SELECTED_NAMESPACE_COOKIE) || "",
  setSelectedNamespace: (ns: string) => {
    setCookieValue(KAGENT_SELECTED_NAMESPACE_COOKIE, ns);
    set({ selectedNamespace: ns });
  },
}));
