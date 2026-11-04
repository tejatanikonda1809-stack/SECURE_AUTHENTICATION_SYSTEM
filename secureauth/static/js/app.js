(() => {
  document.querySelectorAll("[data-toggle-password]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;
      const visible = input.type === "password";
      input.type = visible ? "text" : "password";
      button.textContent = visible ? "Hide" : "Show";
      button.setAttribute("aria-label", visible ? "Hide password" : "Show password");
    });
  });

  const strengthInput = document.querySelector("[data-strength-input]");
  const strengthBar = document.querySelector("[data-strength-bar]");
  const strengthLabel = document.querySelector("[data-strength-label]");
  if (strengthInput && strengthBar && strengthLabel) {
    strengthInput.addEventListener("input", () => {
      const value = strengthInput.value;
      const checks = [
        value.length >= 12,
        /[A-Z]/.test(value),
        /[a-z]/.test(value),
        /\d/.test(value),
        /[^A-Za-z0-9]/.test(value),
      ];
      const score = checks.filter(Boolean).length;
      const strength = score === 5 ? "strong" : score >= 3 ? "medium" : "weak";
      const label = value ? `${strength[0].toUpperCase()}${strength.slice(1)} password` : "Enter a password";
      strengthLabel.textContent = label;
      strengthBar.style.width = `${score * 20}%`;
      strengthBar.dataset.strength = value ? strength : "";
    });
  }
})();
