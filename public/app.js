let socket;

/* ================= EVENT BINDING ================= */

document.addEventListener("DOMContentLoaded", () => {

  document.querySelector(".login-btn")
    ?.addEventListener("click", login);

  document.querySelector(".register-btn")
    ?.addEventListener("click", register);

});

/* ================= LOGIN ================= */

async function login() {

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  try {

    const res = await fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "include",
      body: JSON.stringify({
        username,
        password
      })
    });

    const data = await res.json();

    if (!data.success) {
      document.getElementById("message").innerText =
        data.error || "Login failed";
      return;
    }

    localStorage.setItem("username", username);
    localStorage.setItem("token", data.token);
    localStorage.setItem("role", data.role);

    window.location.href = "/dashboard.html";

  } catch (err) {
    console.log(err);
  }

}

/* ================= REGISTER ================= */

async function register() {

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  try {

    const res = await fetch("/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        username,
        password
      })
    });

    const data = await res.json();

    document.getElementById("message").innerText =
      data.success ? "Registered successfully" : data.error;

  } catch (err) {
    console.log(err);
  }

}