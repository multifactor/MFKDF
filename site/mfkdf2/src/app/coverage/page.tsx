import Jumbotron from "@ui/components/jumbotron";
import Frame from "../frame";

export default function Tests() {
  return (
    <>
      <main className="mt-30 max-w-[100vw] overflow-x-hidden">
        <Jumbotron variant="white">
          <Frame src="/nyc/index.html" extraHeight={100} />
        </Jumbotron>
      </main>
    </>
  );
}
