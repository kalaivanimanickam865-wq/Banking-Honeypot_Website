// Minor UX polish only — no security logic lives client-side.
document.addEventListener("DOMContentLoaded", () => {
  const pwdField = document.getElementById("password");
  if (!pwdField) return;

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.textContent = "Show";
  toggle.className = "btn btn-outline-secondary btn-sm mt-2";
  toggle.addEventListener("click", () => {
    const isHidden = pwdField.type === "password";
    pwdField.type = isHidden ? "text" : "password";
    toggle.textContent = isHidden ? "Hide" : "Show";
  });
  pwdField.insertAdjacentElement("afterend", toggle);
});
