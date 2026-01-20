import { getBackendOrigin } from "@/lib/utils";

export default async function LoginPage({
  searchParams,
}: {
  searchParams?: Promise<{ next?: string }>;
}) {
  const resolved = await searchParams;
  const next = resolved?.next || "/";
  const loginUrl = `${getBackendOrigin()}/auth/login?redirect=${encodeURIComponent(next)}`;

  return (
    <div className="w-full h-full flex items-center justify-center p-6">
      <div className="max-w-md w-full border rounded-lg p-6 space-y-4">
        <h1 className="text-2xl font-semibold">Sign in</h1>
        <p className="text-sm text-muted-foreground">
          You must sign in to access the KAgent dashboard.
        </p>
        <a
          href={loginUrl}
          className="inline-flex items-center justify-center rounded-md text-sm font-medium h-10 px-4 py-2 bg-primary text-primary-foreground w-full"
        >
          Sign in with your organization
        </a>
      </div>
    </div>
  );
}
