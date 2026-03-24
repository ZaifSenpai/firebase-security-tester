import type { Route } from "./+types/home";
import { Welcome } from "../welcome/welcome";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "Firebase Security Tester" },
    {
      name: "description",
      content:
        "Probe Firebase Authentication, Realtime Database, Firestore, and Storage permissions from the browser.",
    },
  ];
}

export default function Home() {
  return <Welcome />;
}
