import { useEffect, useMemo, useRef, useState } from "react";
import JSON5 from "json5";
import {
  deleteApp,
  getApps,
  initializeApp,
  type FirebaseApp,
  type FirebaseOptions,
} from "firebase/app";
import {
  createUserWithEmailAndPassword,
  getAuth,
  signInWithEmailAndPassword,
  signOut,
} from "firebase/auth";
import { getDatabase, get, ref, set } from "firebase/database";
import {
  doc,
  getDoc,
  getFirestore,
  serverTimestamp,
  setDoc,
} from "firebase/firestore";
import { getStorage, listAll, ref as storageRef, uploadBytes } from "firebase/storage";

type ServiceName = "Authentication" | "Realtime Database" | "Firestore" | "Storage";
type AccessMethod = "config" | "accessToken";

type ProbeResult = {
  id: number;
  service: ServiceName;
  action: string;
  path: string;
  success: boolean;
  message: string;
};

const APP_NAME = "firebase-security-tester";
const CONFIG_STORAGE_KEY = "firebase-security-tester-config-v1";

const SAMPLE_CONFIG = JSON.stringify(
  {
    apiKey: "AIza...",
    authDomain: "your-project.firebaseapp.com",
    databaseURL: "https://your-project-id.firebaseio.com",
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

function parseLooseInput(rawText: string): { value?: unknown; error?: string } {
  const trimmed = rawText.trim();
  if (!trimmed) {
    return { value: undefined };
  }

  try {
    try {
      return { value: JSON.parse(trimmed) };
    } catch {
      return { value: JSON5.parse(trimmed) };
    }
  } catch {
    return { error: "Invalid payload format. Use JSON or JavaScript-style object syntax." };
  }
}

function splitEmail(baseEmail: string): { local?: string; domain?: string; error?: string } {
  const trimmed = baseEmail.trim();
  const atIndex = trimmed.indexOf("@");

  if (atIndex <= 0 || atIndex === trimmed.length - 1) {
    return { error: "Base email must look like name@example.com." };
  }

  return {
    local: trimmed.slice(0, atIndex),
    domain: trimmed.slice(atIndex + 1),
  };
}

function toFirestoreValue(value: unknown): Record<string, unknown> {
  if (value === null || value === undefined) {
    return { nullValue: null };
  }

  if (typeof value === "boolean") {
    return { booleanValue: value };
  }

  if (typeof value === "number") {
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }

  if (typeof value === "string") {
    return { stringValue: value };
  }

  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map((item) => toFirestoreValue(item)),
      },
    };
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const fields = Object.fromEntries(entries.map(([key, val]) => [key, toFirestoreValue(val)]));
    return { mapValue: { fields } };
  }

  return { stringValue: String(value) };
}

function fromFirestoreValue(value: Record<string, unknown> | undefined): unknown {
  if (!value) {
    return undefined;
  }

  if ("nullValue" in value) {
    return null;
  }
  if ("booleanValue" in value) {
    return value.booleanValue;
  }
  if ("integerValue" in value) {
    return Number(value.integerValue);
  }
  if ("doubleValue" in value) {
    return value.doubleValue;
  }
  if ("stringValue" in value) {
    return value.stringValue;
  }
  if ("arrayValue" in value) {
    const arrayValue = value.arrayValue as { values?: Record<string, unknown>[] };
    return (arrayValue.values ?? []).map((item) => fromFirestoreValue(item));
  }
  if ("mapValue" in value) {
    const mapValue = value.mapValue as { fields?: Record<string, Record<string, unknown>> };
    const fields = mapValue.fields ?? {};
    return Object.fromEntries(
      Object.entries(fields).map(([key, fieldValue]) => [key, fromFirestoreValue(fieldValue)]),
    );
  }

  return value;
}

async function parseHttpError(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = (await response.json()) as { error?: { message?: string } };
    return body.error?.message ?? `HTTP ${response.status}`;
  }

  const text = await response.text();
  return text || `HTTP ${response.status}`;
}

export function Welcome() {
  const [accessMethod, setAccessMethod] = useState<AccessMethod>("config");
  const [credentialsJson, setCredentialsJson] = useState(SAMPLE_CONFIG);
  const [accessToken, setAccessToken] = useState("");
  const [tokenProjectId, setTokenProjectId] = useState("");
  const [tokenDatabaseUrl, setTokenDatabaseUrl] = useState("");
  const [tokenStorageBucket, setTokenStorageBucket] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [authEmail, setAuthEmail] = useState("testuser@example.com");
  const [authPassword, setAuthPassword] = useState("password123");
  const [bulkBaseEmail, setBulkBaseEmail] = useState("someone@gmail.com");
  const [bulkPassword, setBulkPassword] = useState("password123");
  const [bulkCount, setBulkCount] = useState(100);
  const [databasePathInput, setDatabasePathInput] = useState("/");
  const [databaseWritePayload, setDatabaseWritePayload] = useState(
    JSON.stringify(
      {
        probeSource: "firebase-security-tester",
        note: "DB write probe",
      },
      null,
      2,
    ),
  );
  const [firestorePathInput, setFirestorePathInput] = useState("security_test/root_probe");
  const [firestoreWritePayload, setFirestoreWritePayload] = useState(
    JSON.stringify(
      {
        probeSource: "firebase-security-tester",
        note: "Firestore write probe",
      },
      null,
      2,
    ),
  );
  const [storagePathInput, setStoragePathInput] = useState("security-test");
  const [storageUploadFile, setStorageUploadFile] = useState<File | null>(null);
  const [results, setResults] = useState<ProbeResult[]>([]);
  const [runningAction, setRunningAction] = useState<string | null>(null);
  const [appRefreshMessage, setAppRefreshMessage] = useState("Firebase app not initialized yet.");
  const refreshSeqRef = useRef(0);
  const didRestoreConfigRef = useRef(false);

  const parsedConfig = useMemo(() => parseFirebaseConfig(credentialsJson), [credentialsJson]);
  const isTokenMode = accessMethod === "accessToken";

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const raw = window.localStorage.getItem(CONFIG_STORAGE_KEY);
    if (!raw) {
      didRestoreConfigRef.current = true;
      return;
    }

    try {
      const saved = JSON.parse(raw) as Partial<{
        accessMethod: AccessMethod;
        credentialsJson: string;
        accessToken: string;
        tokenProjectId: string;
        tokenDatabaseUrl: string;
        tokenStorageBucket: string;
        authMode: "login" | "signup";
        authEmail: string;
        authPassword: string;
        bulkBaseEmail: string;
        bulkPassword: string;
        bulkCount: number;
        databasePathInput: string;
        databaseWritePayload: string;
        firestorePathInput: string;
        firestoreWritePayload: string;
        storagePathInput: string;
      }>;

      if (saved.accessMethod === "config" || saved.accessMethod === "accessToken") {
        setAccessMethod(saved.accessMethod);
      }
      if (typeof saved.credentialsJson === "string") {
        setCredentialsJson(saved.credentialsJson);
      }
      if (typeof saved.accessToken === "string") {
        setAccessToken(saved.accessToken);
      }
      if (typeof saved.tokenProjectId === "string") {
        setTokenProjectId(saved.tokenProjectId);
      }
      if (typeof saved.tokenDatabaseUrl === "string") {
        setTokenDatabaseUrl(saved.tokenDatabaseUrl);
      }
      if (typeof saved.tokenStorageBucket === "string") {
        setTokenStorageBucket(saved.tokenStorageBucket);
      }
      if (saved.authMode === "login" || saved.authMode === "signup") {
        setAuthMode(saved.authMode);
      }
      if (typeof saved.authEmail === "string") {
        setAuthEmail(saved.authEmail);
      }
      if (typeof saved.authPassword === "string") {
        setAuthPassword(saved.authPassword);
      }
      if (typeof saved.bulkBaseEmail === "string") {
        setBulkBaseEmail(saved.bulkBaseEmail);
      }
      if (typeof saved.bulkPassword === "string") {
        setBulkPassword(saved.bulkPassword);
      }
      if (typeof saved.bulkCount === "number" && Number.isFinite(saved.bulkCount)) {
        setBulkCount(saved.bulkCount);
      }
      if (typeof saved.databasePathInput === "string") {
        setDatabasePathInput(saved.databasePathInput);
      }
      if (typeof saved.databaseWritePayload === "string") {
        setDatabaseWritePayload(saved.databaseWritePayload);
      }
      if (typeof saved.firestorePathInput === "string") {
        setFirestorePathInput(saved.firestorePathInput);
      }
      if (typeof saved.firestoreWritePayload === "string") {
        setFirestoreWritePayload(saved.firestoreWritePayload);
      }
      if (typeof saved.storagePathInput === "string") {
        setStoragePathInput(saved.storagePathInput);
      }
    } catch {
      // Ignore corrupted storage and keep defaults.
    } finally {
      didRestoreConfigRef.current = true;
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined" || !didRestoreConfigRef.current) {
      return;
    }

    const toStore = {
      accessMethod,
      credentialsJson,
      accessToken,
      tokenProjectId,
      tokenDatabaseUrl,
      tokenStorageBucket,
      authMode,
      authEmail,
      authPassword,
      bulkBaseEmail,
      bulkPassword,
      bulkCount,
      databasePathInput,
      databaseWritePayload,
      firestorePathInput,
      firestoreWritePayload,
      storagePathInput,
    };

    window.localStorage.setItem(CONFIG_STORAGE_KEY, JSON.stringify(toStore));
  }, [
    accessMethod,
    accessToken,
    authEmail,
    authMode,
    authPassword,
    bulkBaseEmail,
    bulkCount,
    bulkPassword,
    credentialsJson,
    databasePathInput,
    databaseWritePayload,
    firestorePathInput,
    firestoreWritePayload,
    tokenDatabaseUrl,
    tokenProjectId,
    tokenStorageBucket,
    storagePathInput,
  ]);

  useEffect(() => {
    if (isTokenMode) {
      const existing = getApps().find((item) => item.name === APP_NAME);
      if (existing) {
        void deleteApp(existing);
      }
      setAppRefreshMessage("Access token mode enabled. SDK app not used.");
      return;
    }

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
  }, [isTokenMode, parsedConfig]);

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
    run: () => Promise<string>,
  ) => {
    setRunningAction(key);

    try {
      const message = await run();
      pushResult({ service, action, path, success: true, message });
    } catch (error) {
      const reason = error instanceof Error ? error.message : "Unknown error";
      pushResult({ service, action, path, success: false, message: reason });
    } finally {
      setRunningAction(null);
    }
  };

  const getSdkApp = () => {
    if (!parsedConfig.config) {
      throw new Error(parsedConfig.error ?? "Invalid Firebase configuration.");
    }

    const existing = getApps().find((item) => item.name === APP_NAME);
    return existing ?? initializeApp(parsedConfig.config, APP_NAME);
  };

  const getAccessToken = () => {
    const token = accessToken.trim();
    if (!token) {
      throw new Error("Access token is required in access token mode.");
    }
    return token;
  };

  const getTokenDatabaseBaseUrl = () => {
    const url = (tokenDatabaseUrl || parsedConfig.config?.databaseURL || "").trim();
    if (!url) {
      throw new Error("Database URL is required for token mode.");
    }
    return url.replace(/\/+$/, "");
  };

  const getTokenProject = () => {
    const project = (tokenProjectId || parsedConfig.config?.projectId || "").trim();
    if (!project) {
      throw new Error("Project ID is required for token mode.");
    }
    return project;
  };

  const getTokenStorageBucketName = () => {
    const raw = (tokenStorageBucket || parsedConfig.config?.storageBucket || "").trim();
    if (!raw) {
      throw new Error("Storage bucket is required for token mode.");
    }
    return raw.replace(/^gs:\/\//, "");
  };

  const runAuthSessionCheck = async () => {
    await withProbe(
      "auth-session",
      "Authentication",
      "Check current session",
      "(n/a)",
      async () => {
        if (isTokenMode) {
          const token = getAccessToken();
          const response = await fetch(
            `https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${encodeURIComponent(token)}`,
          );

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          const tokenInfo = (await response.json()) as Record<string, unknown>;
          return `Access token valid. Subject: ${String(tokenInfo.sub ?? "unknown")}`;
        }

        const auth = getAuth(getSdkApp());
        if (!auth.currentUser) {
          return "No active user session.";
        }
        return `User is signed in with uid: ${auth.currentUser.uid}`;
      },
    );
  };

  const runEmailPasswordAuth = async () => {
    await withProbe(
      authMode === "login" ? "auth-login" : "auth-signup",
      "Authentication",
      authMode === "login" ? "Email/Password login" : "Email/Password signup",
      "(n/a)",
      async () => {
        if (isTokenMode) {
          throw new Error("Email/password auth tests are only available in Firebase config mode.");
        }

        const app = getSdkApp();
        const auth = getAuth(app);
        const email = authEmail.trim();
        const password = authPassword.trim();

        if (!email || !password) {
          throw new Error("Email and password are required.");
        }

        const userCredential =
          authMode === "login"
            ? await signInWithEmailAndPassword(auth, email, password)
            : await createUserWithEmailAndPassword(auth, email, password);

        return `${authMode === "login" ? "Login" : "Signup"} allowed. uid: ${userCredential.user.uid}`;
      },
    );
  };

  const runBulkSignup = async () => {
    await withProbe(
      "auth-bulk-signup",
      "Authentication",
      "Bulk signup",
      "(n/a)",
      async () => {
        if (isTokenMode) {
          throw new Error("Bulk signup is only available in Firebase config mode.");
        }

        const app = getSdkApp();
        const auth = getAuth(app);
        const emailParts = splitEmail(bulkBaseEmail);

        if (emailParts.error || !emailParts.local || !emailParts.domain) {
          throw new Error(emailParts.error ?? "Invalid base email.");
        }

        const total = Number.isFinite(bulkCount) ? Math.floor(bulkCount) : 0;
        if (total <= 0) {
          throw new Error("Bulk count must be at least 1.");
        }

        const password = bulkPassword.trim();
        if (!password) {
          throw new Error("Bulk password is required.");
        }

        for (let index = 1; index <= total; index += 1) {
          const email = `${emailParts.local}${index}@${emailParts.domain}`;

          try {
            await createUserWithEmailAndPassword(auth, email, password);
          } catch (error) {
            const reason = error instanceof Error ? error.message : "Unknown error";
            throw new Error(`Stopped at ${index}/${total} (${email}): ${reason}`);
          }
        }

        return `Bulk signup succeeded. Created ${total} users.`;
      },
    );
  };

  const runSignOut = async () => {
    await withProbe(
      "auth-signout",
      "Authentication",
      "Sign out",
      "(n/a)",
      async () => {
        if (isTokenMode) {
          throw new Error("Sign out is only available in Firebase config mode.");
        }

        const app = getSdkApp();
        const auth = getAuth(app);
        await signOut(auth);
        return "Sign out completed.";
      },
    );
  };

  const runDatabaseRead = async () => {
    const dbPath = normalizeDbPath(databasePathInput);
    await withProbe(
      "db-read",
      "Realtime Database",
      "Read data",
      dbPath,
      async () => {
        if (isTokenMode) {
          const token = getAccessToken();
          const baseUrl = getTokenDatabaseBaseUrl();
          const response = await fetch(
            `${baseUrl}${dbPath}.json?access_token=${encodeURIComponent(token)}`,
          );

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          const payload = (await response.json()) as unknown;
          return payload !== null && payload !== undefined
            ? `Read allowed. Preview: ${safePreview(payload)}`
            : "Read allowed but no data found at this path.";
        }

        const app = getSdkApp();
        const db = getDatabase(app);
        const snapshot = await get(ref(db, dbPath));
        return snapshot.exists()
          ? `Read allowed. Preview: ${safePreview(snapshot.val())}`
          : "Read allowed but no data found at this path.";
      },
    );
  };

  const runDatabaseWrite = async () => {
    const dbPath = normalizeDbPath(databasePathInput);
    await withProbe(
      "db-write",
      "Realtime Database",
      "Write data",
      dbPath,
      async () => {
        const payloadResult = parseLooseInput(databaseWritePayload);
        if (payloadResult.error) {
          throw new Error(payloadResult.error);
        }

        if (isTokenMode) {
          const token = getAccessToken();
          const baseUrl = getTokenDatabaseBaseUrl();
          const response = await fetch(
            `${baseUrl}${dbPath}.json?access_token=${encodeURIComponent(token)}`,
            {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payloadResult.value ?? null),
            },
          );

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          return "Write allowed. Test payload saved via REST API.";
        }

        const app = getSdkApp();
        const db = getDatabase(app);
        await set(ref(db, dbPath), payloadResult.value ?? null);
        return "Write allowed. Test payload saved.";
      },
    );
  };

  const runFirestoreRead = async () => {
    const docPath = normalizeFirestorePath(firestorePathInput);
    await withProbe(
      "firestore-read",
      "Firestore",
      "Read document",
      docPath,
      async () => {
        if (isTokenMode) {
          const token = getAccessToken();
          const projectId = getTokenProject();
          const response = await fetch(
            `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${docPath}`,
            {
              headers: { Authorization: `Bearer ${token}` },
            },
          );

          if (response.status === 404) {
            return "Read allowed but no document found at this path.";
          }

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          const payload = (await response.json()) as { fields?: Record<string, Record<string, unknown>> };
          const plain = Object.fromEntries(
            Object.entries(payload.fields ?? {}).map(([key, value]) => [key, fromFirestoreValue(value)]),
          );

          return `Read allowed. Preview: ${safePreview(plain)}`;
        }

        const app = getSdkApp();
        const database = getFirestore(app);
        const snapshot = await getDoc(doc(database, docPath));
        return snapshot.exists()
          ? `Read allowed. Preview: ${safePreview(snapshot.data())}`
          : "Read allowed but no document found at this path.";
      },
    );
  };

  const runFirestoreWrite = async () => {
    const docPath = normalizeFirestorePath(firestorePathInput);
    await withProbe(
      "firestore-write",
      "Firestore",
      "Write document",
      docPath,
      async () => {
        const payloadResult = parseLooseInput(firestoreWritePayload);
        if (payloadResult.error) {
          throw new Error(payloadResult.error);
        }

        const payload = payloadResult.value;
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
          throw new Error("Firestore write payload must be an object.");
        }

        if (isTokenMode) {
          const token = getAccessToken();
          const projectId = getTokenProject();
          const fields = Object.fromEntries(
            Object.entries(payload as Record<string, unknown>).map(([key, value]) => [
              key,
              toFirestoreValue(value),
            ]),
          );

          const response = await fetch(
            `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${docPath}`,
            {
              method: "PATCH",
              headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ fields }),
            },
          );

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          return "Write allowed. Probe fields written via REST API.";
        }

        const app = getSdkApp();
        const database = getFirestore(app);
        await setDoc(
          doc(database, docPath),
          { ...payload, probedAt: serverTimestamp() },
          { merge: true },
        );

        return "Write allowed. Probe fields merged into document.";
      },
    );
  };

  const runStorageList = async () => {
    const normalizedPath = normalizeStoragePath(storagePathInput);
    const path = normalizedPath || "/";

    await withProbe(
      "storage-list",
      "Storage",
      "List objects",
      path,
      async () => {
        if (isTokenMode) {
          const token = getAccessToken();
          const bucket = getTokenStorageBucketName();
          const queryPath = normalizedPath ? `${normalizedPath}/` : "";
          const response = await fetch(
            `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o?delimiter=%2F&prefix=${encodeURIComponent(queryPath)}`,
            {
              headers: { Authorization: `Bearer ${token}` },
            },
          );

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          const payload = (await response.json()) as { items?: unknown[]; prefixes?: unknown[] };
          return `List allowed. Found ${(payload.items ?? []).length} files and ${(payload.prefixes ?? []).length} folders.`;
        }

        const app = getSdkApp();
        const storage = getStorage(app);
        const rootReference = storageRef(storage, normalizedPath);
        const listResult = await listAll(rootReference);

        return `List allowed. Found ${listResult.items.length} files and ${listResult.prefixes.length} folders.`;
      },
    );
  };

  const runStorageWrite = async () => {
    const normalizedPath = normalizeStoragePath(storagePathInput);

    if (!storageUploadFile) {
      pushResult({
        service: "Storage",
        action: "Upload object",
        path: normalizedPath || "/",
        success: false,
        message: "Select a file before running upload.",
      });
      return;
    }

    const targetPath =
      normalizedPath.length === 0
        ? `security-test/${storageUploadFile.name}`
        : normalizedPath.endsWith("/")
          ? `${normalizedPath}${storageUploadFile.name}`
          : normalizedPath;

    await withProbe(
      "storage-write",
      "Storage",
      "Upload object",
      targetPath,
      async () => {
        if (isTokenMode) {
          const token = getAccessToken();
          const bucket = getTokenStorageBucketName();
          const response = await fetch(
            `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?uploadType=media&name=${encodeURIComponent(targetPath)}`,
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": storageUploadFile.type || "application/octet-stream",
              },
              body: storageUploadFile,
            },
          );

          if (!response.ok) {
            throw new Error(await parseHttpError(response));
          }

          return "Upload allowed. Probe file saved via REST API.";
        }

        const app = getSdkApp();
        const storage = getStorage(app);
        await uploadBytes(storageRef(storage, targetPath), storageUploadFile, {
          contentType: storageUploadFile.type || "application/octet-stream",
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
        <label htmlFor="access-method" className="block text-sm font-semibold text-slate-900">
          Access method
        </label>
        <select
          id="access-method"
          className="mt-2 w-full rounded-xl border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-slate-500 focus:outline-none"
          value={accessMethod}
          onChange={(event) => setAccessMethod(event.target.value as AccessMethod)}
        >
          <option value="config">Firebase Config (SDK)</option>
          <option value="accessToken">Access Token (REST API)</option>
        </select>

        {isTokenMode && (
          <div className="mt-4 grid gap-2">
            <label htmlFor="access-token" className="text-sm font-semibold text-slate-900">
              Access token
            </label>
            <textarea
              id="access-token"
              className="min-h-24 w-full rounded-xl border border-slate-300 p-3 font-mono text-xs text-slate-900 focus:border-slate-500 focus:outline-none"
              value={accessToken}
              onChange={(event) => setAccessToken(event.target.value)}
              placeholder="ya29..."
            />
            <label htmlFor="token-project-id" className="mt-2 text-xs font-medium text-slate-700">
              Project ID
            </label>
            <input
              id="token-project-id"
              type="text"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={tokenProjectId}
              onChange={(event) => setTokenProjectId(event.target.value)}
              placeholder="your-project-id"
            />
            <label htmlFor="token-database-url" className="text-xs font-medium text-slate-700">
              Realtime Database URL
            </label>
            <input
              id="token-database-url"
              type="text"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={tokenDatabaseUrl}
              onChange={(event) => setTokenDatabaseUrl(event.target.value)}
              placeholder="https://your-project-id.firebaseio.com"
            />
            <label htmlFor="token-storage-bucket" className="text-xs font-medium text-slate-700">
              Storage Bucket
            </label>
            <input
              id="token-storage-bucket"
              type="text"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={tokenStorageBucket}
              onChange={(event) => setTokenStorageBucket(event.target.value)}
              placeholder="your-project.appspot.com"
            />
            <p className="text-xs text-slate-600">
              Token mode runs service probes via REST API calls with Authorization: Bearer token.
            </p>
          </div>
        )}

        {!isTokenMode && (
          <>
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
          </>
        )}
      </section>

      <section className="grid gap-4">
        <details className="rounded-2xl border border-slate-200 bg-white p-4" open>
          <summary className="cursor-pointer text-sm font-semibold text-slate-900">Authentication</summary>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <label className="text-xs font-medium text-slate-700" htmlFor="auth-mode">
              Mode
            </label>
            <select
              id="auth-mode"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={authMode}
              onChange={(event) => setAuthMode(event.target.value as "login" | "signup")}
            >
              <option value="login">Email/Password Login</option>
              <option value="signup">Email/Password Signup</option>
            </select>

            <label className="text-xs font-medium text-slate-700" htmlFor="auth-email">
              Email
            </label>
            <input
              id="auth-email"
              type="email"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={authEmail}
              onChange={(event) => setAuthEmail(event.target.value)}
            />

            <label className="text-xs font-medium text-slate-700" htmlFor="auth-password">
              Password
            </label>
            <input
              id="auth-password"
              type="password"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={authPassword}
              onChange={(event) => setAuthPassword(event.target.value)}
            />
          </div>

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
              onClick={runEmailPasswordAuth}
              disabled={Boolean(runningAction)}
            >
              {authMode === "login" ? "Run Login" : "Run Signup"}
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

          <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs font-semibold text-slate-800">Bulk Signup</p>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <label className="text-xs font-medium text-slate-700" htmlFor="bulk-base-email">
                Base email
              </label>
              <input
                id="bulk-base-email"
                type="email"
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
                value={bulkBaseEmail}
                onChange={(event) => setBulkBaseEmail(event.target.value)}
              />

              <label className="text-xs font-medium text-slate-700" htmlFor="bulk-password">
                Password
              </label>
              <input
                id="bulk-password"
                type="password"
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
                value={bulkPassword}
                onChange={(event) => setBulkPassword(event.target.value)}
              />

              <label className="text-xs font-medium text-slate-700" htmlFor="bulk-count">
                Count
              </label>
              <input
                id="bulk-count"
                type="number"
                min={1}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
                value={bulkCount}
                onChange={(event) => setBulkCount(Number(event.target.value))}
              />
            </div>
            <p className="mt-2 text-xs text-slate-600">
              Example: someone@gmail.com creates someone1@gmail.com to someoneN@gmail.com.
            </p>
            <button
              type="button"
              className="mt-3 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-50"
              onClick={runBulkSignup}
              disabled={Boolean(runningAction)}
            >
              Run Bulk Signup
            </button>
          </div>
          {renderServiceResults("Authentication")}
        </details>

        <details className="rounded-2xl border border-slate-200 bg-white p-4" open>
          <summary className="cursor-pointer text-sm font-semibold text-slate-900">Realtime Database</summary>
          <div className="mt-4 grid gap-2">
            <label className="text-xs font-medium text-slate-700" htmlFor="db-path">
              Probe path
            </label>
            <input
              id="db-path"
              type="text"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={databasePathInput}
              onChange={(event) => setDatabasePathInput(event.target.value)}
              placeholder="/"
            />
            <label className="mt-2 text-xs font-medium text-slate-700" htmlFor="db-payload">
              Write payload (JSON or JS object syntax)
            </label>
            <textarea
              id="db-payload"
              className="min-h-28 rounded-lg border border-slate-300 p-3 font-mono text-xs text-slate-900"
              value={databaseWritePayload}
              onChange={(event) => setDatabaseWritePayload(event.target.value)}
            />
          </div>
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
          <div className="mt-4 grid gap-2">
            <label className="text-xs font-medium text-slate-700" htmlFor="firestore-path">
              Document path
            </label>
            <input
              id="firestore-path"
              type="text"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={firestorePathInput}
              onChange={(event) => setFirestorePathInput(event.target.value)}
              placeholder="security_test/root_probe"
            />
            <label
              className="mt-2 text-xs font-medium text-slate-700"
              htmlFor="firestore-payload"
            >
              Write payload (object syntax)
            </label>
            <textarea
              id="firestore-payload"
              className="min-h-28 rounded-lg border border-slate-300 p-3 font-mono text-xs text-slate-900"
              value={firestoreWritePayload}
              onChange={(event) => setFirestoreWritePayload(event.target.value)}
            />
          </div>
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
          <div className="mt-4 grid gap-2">
            <label className="text-xs font-medium text-slate-700" htmlFor="storage-path">
              Path (folder or full object path)
            </label>
            <input
              id="storage-path"
              type="text"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              value={storagePathInput}
              onChange={(event) => setStoragePathInput(event.target.value)}
              placeholder="security-test/"
            />
            <label className="mt-2 text-xs font-medium text-slate-700" htmlFor="storage-file">
              File to upload
            </label>
            <input
              id="storage-file"
              type="file"
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900"
              onChange={(event) => {
                const selected = event.target.files?.[0] ?? null;
                setStorageUploadFile(selected);
              }}
            />
            {storageUploadFile && (
              <p className="text-xs text-slate-600">Selected: {storageUploadFile.name}</p>
            )}
            <p className="text-xs text-slate-600">
              Note: browsers do not allow restoring file inputs after reload. Re-select the file each time.
            </p>
          </div>
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
