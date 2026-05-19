const express = require("express");

const app = express();

app.use(express.json());

// =====================================
// META FLOW VERIFICATION
// =====================================

app.post("/", (req, res) => {

    console.log("BODY:");
    console.log(req.body);

    // IMPORTANT:
    // RETURN PLAIN TEXT
    // NOT JSON

    return res
        .status(200)
        .send("OK");
});

// =====================================
// HEALTH CHECK
// =====================================

app.get("/", (req, res) => {

    res.send(
        "WhatsApp Flow Endpoint Running"
    );
});

// =====================================
// START SERVER
// =====================================

const PORT =
    process.env.PORT || 3000;

app.listen(PORT, () => {

    console.log(
        "Server Running on Port",
        PORT
    );
});
