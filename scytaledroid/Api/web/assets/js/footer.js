function buildFooter() {
  const year = new Date().getFullYear();
  return `
    <div class="footer-left">ScytaleDroid API UI</div>
    <div class="footer-right">© ${year}</div>
  `;
}

document.addEventListener("DOMContentLoaded", () => {
  const footer = document.getElementById("pageFooter");
  if (footer) {
    footer.innerHTML = buildFooter();
  }
});
