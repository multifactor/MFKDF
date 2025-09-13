import Frame from "../frame";

export default function Tests() {
  return (
    <>
      <main className="mt-30 max-w-[100vw] overflow-x-hidden">
        <Frame src="/mochawesome/mochawesome.html" extraHeight={100} />
      </main>
    </>
  );
}
