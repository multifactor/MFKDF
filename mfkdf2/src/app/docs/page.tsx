import { redirect } from "next/navigation";

export default async function docs() {
  return redirect("/docs/index");
}
