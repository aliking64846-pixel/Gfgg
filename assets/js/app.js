(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const dialog = $("#about-dialog");
  const toast = $("#toast");
  const STORAGE_KEY = "mustaqbali100-social-studies-v1";
  let toastTimer;

  function notify(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2600);
  }

  function loadProgress() {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      $("#completed-count").textContent = Number(saved.completedCount) || 0;
      $("#completion-rate").textContent = (Number(saved.completionRate) || 0) + "%";
      $("#review-count").textContent = Number(saved.reviewCount) || 0;
    } catch (error) {
      console.warn("تعذر تحميل التقدم المحلي:", error);
    }
  }

  $("#about-button")?.addEventListener("click", () => {
    if (typeof dialog?.showModal === "function") dialog.showModal();
    else notify("مستقبلي 100 — نموذج تأسيسي للاجتماعيات.");
  });
  $("#close-about")?.addEventListener("click", () => dialog?.close());
  $("#confirm-about")?.addEventListener("click", () => dialog?.close());

  $("#sound-toggle")?.addEventListener("click", (event) => {
    const button = event.currentTarget;
    const pressed = button.getAttribute("aria-pressed") === "true";
    button.setAttribute("aria-pressed", String(!pressed));
    button.textContent = pressed ? "♫" : "🔇";
    notify(pressed ? "تم تفعيل مؤشر الصوت." : "تم إيقاف مؤشر الصوت. لا توجد مؤثرات صوتية مضافة في هذا الإصدار.");
  });

  $("#lesson-search")?.addEventListener("input", (event) => {
    const query = event.target.value.trim();
    if (query) notify("سيُفعّل البحث داخل فهرس الدروس بعد إضافة محتوى الكتاب المعتمد.");
  });

  document.querySelectorAll('.bottom-nav a[href^="#"]').forEach((link) => {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
      link.classList.add("active");
    });
  });

  loadProgress();
})();