"use client";

import React from "react";
import { useNamespaceStore } from "@/lib/namespaceStore";

export function NamespaceGate({ children }: { children: React.ReactNode }) {
  const { selectedNamespace } = useNamespaceStore();

  if (!selectedNamespace) {
    return (
      <div className="max-w-6xl mx-auto px-4 md:px-6 py-10">
        <div className="rounded-lg border p-6">
          <div className="text-lg font-medium">Select a namespace to continue</div>
          <div className="text-sm text-muted-foreground mt-2">
            Choose a namespace from the selector in the header. Only resources you are authorized to access will be available.
          </div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
