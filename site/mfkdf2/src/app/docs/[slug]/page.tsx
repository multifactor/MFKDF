import { promises as fs } from "fs";
import path from "path"; // Import the path module
import Frame from "../../frame";
import Jumbotron from "@ui/components/jumbotron";

export async function generateStaticParams() {
  const filePath = path.join(process.cwd(), "public", "docs");
  const files = await fs.readdir(filePath);
  const paths = files
    .filter((file) => file.endsWith(".html"))
    .map((file) => ({ slug: file.replace(".html", "") }));
  return paths;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;

  const filePath = path.join(process.cwd(), "public", "docs", `${slug}.html`);
  const htmlContent = await fs.readFile(filePath, "utf8");
  const titleMatch = htmlContent.match(/<title>(.*?)<\/title>/);
  const title = titleMatch ? titleMatch[1] : "Documentation";
  return {
    title,
    description:
      "Documentation for the JavaScript implementation of the Next-Generation Multi-Factor Key Derivation Function (MFKDF2).",
  };
}

export default async function docs({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;

  const filePath = path.join(process.cwd(), "public", "docs", slug + ".html");
  const htmlContent = await fs.readFile(filePath, "utf8");

  return (
    <>
      <main className="mt-30 max-w-[100vw] overflow-x-hidden">
        <Jumbotron variant="white">
          <Frame htmlContent={htmlContent} />
        </Jumbotron>
      </main>
    </>
  );
}
