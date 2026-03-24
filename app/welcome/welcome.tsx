import { useEffect, useMemo, useRef, useState } from "react";
import JSON5 from "json5";
import {
  deleteApp,
  getApps,
  initializeApp,
  type FirebaseApp,
  type FirebaseOptions,
} from "firebase/app";
import { getAuth, signInAnonymously, signOut } from "firebase/auth";
import { getDatabase, get, ref, set } from "firebase/database";
import {
  doc,
  getDoc,
  getFirestore,
  serverTimestamp,
  setDoc,
} from "firebase/firestore";
import { getStorage, listAll, ref as storageRef, uploadString } from "firebase/storage";

type ServiceName = "Authentication" | "Realtime Database" | "Firestore" | "Storage";

type ProbeResult = {
  id: number;
  service: ServiceName;
  action: string;
  path: string;
  success: boolean;
  message: string;
};

const APP_NAME = "firebase-security-tester";

const SAMPLE_CONFIG = JSON.stringify(
  {
    apiKey: "AIza...",
    authDomain: "your-project.firebaseapp.com",
    databaseURL: "https://your-project-default-rtdb.firebaseio.com",
    projectId: "your-project-id",
    storageBucket: "your-project.appspot.com",
    messagingSenderId: "1234567890",
    appId: "1:1234567890:web:abcd1234",
  },
  null,
  2,
);

function safePreview(value: unknown): string {
  const stringValue = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  if (!stringValue) {
    return "(empty result)";
  }

  return stringValue.length > 240 ? `${stringValue.slice(0, 240)}...` : stringValue;
}

function normalizeDbPath(pathInput: string): string {
  const trimmed = pathInput.trim();
  if (!trimmed || trimmed === "/") {
    return "/";
  }

  return `/${trimmed.replace(/^\/+/, "")}`;
}

function normalizeFirestorePath(pathInput: string): string {
  const trimmed = pathInput.trim().replace(/^\/+|\/+$/g, "");
  if (!trimmed) {
    return "security_test/root_probe";
  }

  const segments = trimmed.split("/").filter(Boolean);
  if (segments.length % 2 === 0) {
    return trimmed;
  }

  return `${trimmed}/probe_doc`;
}

function normalizeStoragePath(pathInput: string): string {
  return pathInput.trim().replace(/^\/+|\/+$/g, "");
}

function parseFirebaseConfig(rawText: string): { config?: FirebaseOptions; error?: string } {
  try {
    let parsed: Record<string, unknown>;

    try {
      parsed = JSON.parse(rawText) as Record<string, unknown>;
    } catch {
      parsed = JSON5.parse(rawText) as Record<string, unknown>;
    }

    const maybeConfig = (parsed.firebaseConfig ?? parsed) as Record<string, unknown>;

    if (typeof maybeConfig.apiKey !== "string" || typeof maybeConfig.projectId !== "string") {
      return {
        error: "Config must include at least apiKey and projectId for client-side testing.",
      };
    }

    return { config: maybeConfig as FirebaseOptions };
  } catch {
    return {
      error:
        "Invalid config format. Paste valid JSON or JavaScript-style object syntax (JSON5 supported).",
    };
  }
}

export function Welcome() {
  const [credentialsJson, setCredentialsJson] = useState(SAMPLE_CONFIG);
  const [pathInput, setPathInput] = useState("/");
  const [results, setResults] = useState<ProbeResult[]>([]);
  const [runningAction, setRunningAction] = useState<string | null>(null);
  const [appRefreshMessage, setAppRefreshMessage] = useState("Firebase app not initialized yet.");
  const refreshSeqRef = useRef(0);

  const parsedConfig = useMemo(() => parseFirebaseConfig(credentialsJson), [credentialsJson]);

  useEffect(() => {
    const refreshId = refreshSeqRef.current + 1;
    refreshSeqRef.current = refreshId;

    const refreshAppInstance = async () => {
      const existing = getApps().find((item) => item.name === APP_NAME);
      if (existing) {
        await deleteApp(existing);
      }

      if (!parsedConfig.config) {
        if (refreshSeqRef.current === refreshId) {
          setAppRefreshMessage("Invalid config. Existing app instance cleared.");
        }
        return;
      }

      initializeApp(parsedConfig.config, APP_NAME);
      if (refreshSeqRef.current === refreshId) {
        setAppRefreshMessage("Firebase app instance refreshed.");
      }
    };

    void refreshAppInstance().catch((error: unknown) => {
      if (refreshSeqRef.current !== refreshId) {
        return;
      }

      const reason = error instanceof Error ? error.message : "Unknown error while refreshing app.";
      setAppRefreshMessage(`Failed to refresh app: ${reason}`);
    });
  }, [parsedConfig]);

  const pushResult = (next: Omit<ProbeResult, "id">) => {
    setResults((current) => [{ ...next, id: Date.now() + Math.random() }, ...current]);
  };

  const clearResultsForService = (service: ServiceName) => {
    setResults((current) => current.filter((item) => item.service !== service));
  };

  const getResultsForService = (service: ServiceName) => {
    return results.filter((item) => item.service === service);
  };

  const renderServiceResults = (service: ServiceName) => {
    const serviceResults = getResultsForService(service);

    return (
      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-semibold text-slate-800">Results</h3>
          <button
            type="button"
            className="rounded-md border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-100"
            onClick={() => clearResultsForService(service)}
          >
            Clear
          </button>
        </div>

        <ul className="mt-2 space-y-2">
          {serviceResults.length === 0 && (
            <li className="rounded-md border border-dashed border-slate-300 p-2 text-xs text-slate-500">
              No tests run in this category yet.
            </li>
          )}
          {serviceResults.map((result) => (
            <li
              key={result.id}
              className={`rounded-md border p-2 text-xs ${
                result.success
                  ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                  : "border-red-200 bg-red-50 text-red-900"
              }`}
            >
              <p className="font-semibold">{result.action}</p>
              <p>Path: {result.path}</p>
              <p className="mt-1">{result.message}</p>
            </li>
          ))}
        </ul>
      </div>
    );
  };

  const withProbe = async (
    key: string,
    service: ProbeResult["service"],
    action: string,
    path: string,
    run: (app: FirebaseApp) => Promise<string>,
  ) => {
    if (!parsedConfig.config) {
      pushResult({
        service,
        action,
        path,
        success: false,
        message: parsedConfig.error ?? "Invalid Firebase configuration.",
      });
      return;
    }

    setRunningAction(key);
    let app: FirebaseApp | undefined;

    try {
      const existing = getApps().find((item) => item.name === APP_NAME);
      app = existing ?? initializeApp(parsedConfig.config, APP_NAME);

      const message = await run(app);
      pushResult({ service, action, path, success: true, message });
    } catch (error) {
      const reason = error instanceof Error ? error.message : "Unknown error";
      pushResult({ service, action, path, success: false, message: reason });
    } finally {
      setRunningAction(null);
    }
  };

  const runAuthSessionCheck = async () => {
    await withProbe(
      "auth-session",
      "Authentication",
      "Check current session",
      "(n/a)",
      async (app) => {
        const auth = getAuth(app);
        if (!auth.currentUser) {
          return "No active user session.";
        }

        return `User is signed in with uid: ${auth.currentUser.uid}`;
      },
    );
  };

  const runAnonymousSignIn = async () => {
    await withProbe(
      "auth-anonymous",
      "Authentication",
      "Anonymous sign in",
      "(n/a)",
      async (app) => {
        const auth = getAuth(app);
        const userCredential = await signInAnonymously(auth);
        return `Sign in allowed. uid: ${userCredential.user.uid}`;
      },
    );
  };

  const runSignOut = async () => {
    await withProbe(
      "auth-signout",
      "Authentication",
      "Sign out",
      "(n/a)",
      async (app) => {
        const auth = getAuth(app);
        await signOut(auth);
        return "Sign out completed.";
      },
    );
  };

  const runDatabaseRead = async () => {
    const dbPath = normalizeDbPath(pathInput);
    await withProbe(
      "db-read",
      "Realtime Database",
      "Read data",
      dbPath,
      async (app) => {
        const db = getDatabase(app);
        const snapshot = await get(ref(db, dbPath));
        return snapshot.exists()
          ? `Read allowed. Preview: ${safePreview(snapshot.val())}`
          : "Read allowed but no data found at this path.";
      },
    );
  };

  const runDatabaseWrite = async () => {
    const dbPath = normalizeDbPath(pathInput);
    await withProbe(
      "db-write",
      "Realtime Database",
      "Write data",
      dbPath,
      async (app) => {
        const db = getDatabase(app);
        await set(ref(db, dbPath), {
          probeSource: "firebase-security-tester",
          probedAt: new Date().toISOString(),
        });
        return "Write allowed. Test payload saved.";
      },
    );
  };

  const runFirestoreRead = async () => {
    const docPath = normalizeFirestorePath(pathInput);
    await withProbe(
      "firestore-read",
      "Firestore",
      "Read document",
      docPath,
      async (app) => {
        const database = getFirestore(app);
        const snapshot = await getDoc(doc(database, docPath));
        return snapshot.exists()
          ? `Read allowed. Preview: ${safePreview(snapshot.data())}`
          : "Read allowed but no document found at this path.";
      },
    );
  };

  const runFirestoreWrite = async () => {
    const docPath = normalizeFirestorePath(pathInput);
    await withProbe(
      "firestore-write",
      "Firestore",
      "Write document",
      docPath,
      async (app) => {
        const database = getFirestore(app);
        await setDoc(
          doc(database, docPath),
          {
            probeSource: "firebase-security-tester",
            probedAt: serverTimestamp(),
            note: "Write probe from browser",
          },
          { merge: true },
        );

        return "Write allowed. Probe fields merged into document.";
      },
    );
  };

  const runStorageList = async () => {
    const normalizedPath = normalizeStoragePath(pathInput);
    const path = normalizedPath || "/";

    await withProbe(
      "storage-list",
      "Storage",
      "List objects",
      path,
      async (app) => {
        const storage = getStorage(app);
        const rootReference = storageRef(storage, normalizedPath);
        const listResult = await listAll(rootReference);

        return `List allowed. Found ${listResult.items.length} files and ${listResult.prefixes.length} folders.`;
      },
    );
  };

  const runStorageWrite = async () => {
    const normalizedPath = normalizeStoragePath(pathInput);
    const targetPath = normalizedPath
      ? `${normalizedPath.replace(/\/+$/g, "")}/probe.json`
      : "security-test/probe.json";

    await withProbe(
      "storage-write",
      "Storage",
      "Upload object",
      targetPath,
      async (app) => {
        const storage = getStorage(app);
        const payload = JSON.stringify(
          {
            probeSource: "firebase-security-tester",
            probedAt: new Date().toISOString(),
          },
          null,
          2,
        );

        await uploadString(storageRef(storage, targetPath), payload, "raw", {
          contentType: "application/json",
        });

        return "Upload allowed. Probe file saved.";
      },
    );
  };

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-6xl flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8">
      <header className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
        <h1 className="text-2xl font-bold text-slate-900">Firebase Security Tester</h1>
        <p className="mt-2 text-sm text-slate-700">
          Paste Firebase web config JSON, then run probes against Authentication,
          Realtime Database, Firestore, and Storage.
        </p>
      </header>

      <section className="rounded-2xl border border-slate-200 bg-white p-5">
        <label htmlFor="firebase-config" className="block text-sm font-semibold text-slate-900">
          Firebase credentials JSON
        </label>
        <textarea
          id="firebase-config"
          className="mt-2 min-h-48 w-full rounded-xl border border-slate-300 p-3 font-mono text-xs text-slate-900 focus:border-slate-500 focus:outline-none"
          value={credentialsJson}
          onChange={(event) => setCredentialsJson(event.target.value)}
          aria-describedby="firebase-config-help"
        />
        <p id="firebase-config-help" className="mt-2 text-xs text-slate-600">
          Supports JSON and JavaScript-style object syntax (e.g. unquoted keys). Expected keys:
          apiKey, projectId, appId, and optional authDomain/databaseURL/storageBucket.
        </p>
        <p className="mt-2 text-xs text-slate-600">{appRefreshMessage}</p>
        {parsedConfig.error && (
          <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{parsedConfig.error}</p>
        )}
      </section>

      <section className="rounded-2xl border border-slate-200 bg-white p-5">
        <label htmlFor="probe-path" className="block text-sm font-semibold text-slate-900">
          Path to probe (root first)
        </label>
        <input
          id="probe-path"
          type="text"
          className="mt-2 w-full rounded-xl border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-slate-500 focus:outline-none"
          placeholder="/"
          value={pathInput}
          onChange={(event) => setPathInput(event.target.value)}
        />
        <p className="mt-2 text-xs text-slate-600">
          Realtime Database and Storage can probe from root (/). Firestore converts empty path to
          security_test/root_probe.
        </p>
      </section>

      <section className="grid gap-4">
        <details className="rounded-2xl border border-slate-200 bg-white p-4" open>
          <summary className="cursor-pointer text-sm font-semibold text-slate-900">Authentication</summary>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded-lg bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runAuthSessionCheck}
              disabled={Boolean(runningAction)}
            >
              Check Session
            </button>
            <button
              type="button"
              className="rounded-lg bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runAnonymousSignIn}
              disabled={Boolean(runningAction)}
            >
              Anonymous Sign In
            </button>
            <button
              type="button"
              className="rounded-lg bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runSignOut}
              disabled={Boolean(runningAction)}
            >
              Sign Out
            </button>
          </div>
          {renderServiceResults("Authentication")}
        </details>

        <details className="rounded-2xl border border-slate-200 bg-white p-4" open>
          <summary className="cursor-pointer text-sm font-semibold text-slate-900">Realtime Database</summary>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded-lg bg-emerald-700 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runDatabaseRead}
              disabled={Boolean(runningAction)}
            >
              Read
            </button>
            <button
              type="button"
              className="rounded-lg bg-emerald-700 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runDatabaseWrite}
              disabled={Boolean(runningAction)}
            >
              Write
            </button>
          </div>
          {renderServiceResults("Realtime Database")}
        </details>

        <details className="rounded-2xl border border-slate-200 bg-white p-4" open>
          <summary className="cursor-pointer text-sm font-semibold text-slate-900">Firestore</summary>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded-lg bg-amber-700 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runFirestoreRead}
              disabled={Boolean(runningAction)}
            >
              Read Document
            </button>
            <button
              type="button"
              className="rounded-lg bg-amber-700 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runFirestoreWrite}
              disabled={Boolean(runningAction)}
            >
              Write Document
            </button>
          </div>
          {renderServiceResults("Firestore")}
        </details>

        <details className="rounded-2xl border border-slate-200 bg-white p-4" open>
          <summary className="cursor-pointer text-sm font-semibold text-slate-900">Storage</summary>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              className="rounded-lg bg-indigo-700 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runStorageList}
              disabled={Boolean(runningAction)}
            >
              List
            </button>
            <button
              type="button"
              className="rounded-lg bg-indigo-700 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runStorageWrite}
              disabled={Boolean(runningAction)}
            >
              Upload
            </button>
          </div>
          {renderServiceResults("Storage")}
        </details>
      </section>
    </main>
  );
}
