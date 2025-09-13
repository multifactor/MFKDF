"use client";

import { useEffect } from "react";

export default function Frame({
  htmlContent,
  src,
  extraHeight = 0,
}: {
  htmlContent?: string;
  src?: string;
  extraHeight?: number;
}) {
  useEffect(() => {
    let resized = false;

    setInterval(() => {
      const iframe = document.querySelector("iframe");
      if (iframe && iframe.contentWindow) {
        iframe.style.height =
          iframe.contentWindow.document.body.scrollHeight + extraHeight + "px";
        if (!resized) scroll();
        resized = true;
      }
    }, 30);

    // on page # change, scroll to # location in iframe
    function scroll() {
      const iframe = document.querySelector("iframe");
      if (iframe && iframe.contentWindow) {
        const hash = window.location.hash;
        const element = iframe.contentWindow.document.getElementById(
          hash.slice(1)
        );
        if (element) {
          const y = element.getBoundingClientRect().top + window.scrollY + 30;

          window.scrollTo({ top: y, behavior: "smooth" });
        }
      }
    }
    window.addEventListener("hashchange", () => {
      scroll();
    });
  }, []);

  if (htmlContent) {
    // set all <a> to target="_parent"
    htmlContent = htmlContent.replace(/<a /g, '<a target="_parent" ');

    // replace all .html links
    htmlContent = htmlContent.replace(/\.html/g, "");

    return <iframe srcDoc={htmlContent} className="w-full"></iframe>;
  } else if (src) {
    return <iframe src={src} className="w-full"></iframe>;
  }
}
