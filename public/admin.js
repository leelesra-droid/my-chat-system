/* =========================================
   Admin Page Protection
========================================= */

const role = localStorage.getItem("role");

// If not admin → redirect to login page
if (!role || role !== "admin") {
    window.location.href = "/";
}

/* =========================================
   Admin Broadcast Function (Optional Starter)
========================================= */

async function broadcastMessage() {

    const message = document.getElementById("broadcastInput").value;

    if (!message) return alert("Enter message");

    try {

        await fetch("/broadcast", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ message })
        });

        alert("Broadcast sent!");

    } catch (err) {
        console.error(err);
        alert("Broadcast failed");
    }
}