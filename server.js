const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

const app = express();

app.use(express.json({
    limit: "5mb"
}));

// =========================================
// LOAD PRIVATE KEY
// =========================================

const privateKey = fs.readFileSync(
    "./private.pem",
    "utf8"
);

// =========================================
// MAIN FLOW ENDPOINT
// =========================================

app.post("/", async (req, res) => {

    try {

        console.log("================================");
        console.log("INCOMING REQUEST");
        console.log(JSON.stringify(req.body, null, 2));
        console.log("================================");

        // =========================================
        // META ENDPOINT VERIFICATION MODE
        // =========================================

        if (req.body.challenge) {

            console.log(
                "FLOW VERIFICATION MODE"
            );

            return res
                .status(200)
                .send(req.body.challenge);
        }

        // =========================================
        // ENCRYPTED FLOW MODE
        // =========================================

        const {
            encrypted_flow_data,
            encrypted_aes_key,
            initial_vector
        } = req.body;

        // =========================================
        // RSA DECRYPT AES KEY
        // =========================================

        const aesKey = crypto.privateDecrypt(
            {
                key: privateKey,

                padding:
                    crypto.constants
                    .RSA_PKCS1_OAEP_PADDING,

                oaepHash: "sha256"
            },

            Buffer.from(
                encrypted_aes_key,
                "base64"
            )
        );

        // =========================================
        // REQUEST IV
        // =========================================

        const iv = Buffer.from(
            initial_vector,
            "base64"
        );

        // =========================================
        // FLOW DATA
        // =========================================

        const flowData = Buffer.from(
            encrypted_flow_data,
            "base64"
        );

        // =========================================
        // SPLIT AUTH TAG
        // =========================================

        const authTag =
            flowData.slice(-16);

        const cipherText =
            flowData.slice(0, -16);

        // =========================================
        // DECRYPT FLOW DATA
        // =========================================

        const decipher =
            crypto.createDecipheriv(
                "aes-128-gcm",
                aesKey,
                iv
            );

        decipher.setAuthTag(authTag);

        let decrypted =
            decipher.update(
                cipherText,
                null,
                "utf8"
            );

        decrypted +=
            decipher.final("utf8");

        console.log("================================");
        console.log("DECRYPTED FLOW DATA");
        console.log(decrypted);
        console.log("================================");

        // =========================================
        // RESPONSE OBJECT
        // =========================================

        const responseObj = {
            version: "3.0",
            screen: "SUCCESS",
            data: {
                status: "active"
            }
        };

        const responseJson =
            JSON.stringify(responseObj);

        // =========================================
        // IMPORTANT:
        // RESPONSE IV = BITWISE NOT OF REQUEST IV
        // =========================================

        const responseIV =
            Buffer.from(iv);

        for (
            let i = 0;
            i < responseIV.length;
            i++
        ) {
            responseIV[i] =
                ~responseIV[i];
        }

        // =========================================
        // ENCRYPT RESPONSE
        // =========================================

        const cipher =
            crypto.createCipheriv(
                "aes-128-gcm",
                aesKey,
                responseIV
            );

        let encrypted =
            cipher.update(
                responseJson,
                "utf8"
            );

        encrypted = Buffer.concat([
            encrypted,
            cipher.final()
        ]);

        const responseTag =
            cipher.getAuthTag();

        // =========================================
        // APPEND AUTH TAG
        // =========================================

        const finalPayload =
            Buffer.concat([
                encrypted,
                responseTag
            ]);

        // =========================================
        // FINAL RESPONSE
        // =========================================

        const finalResponse = {

            encrypted_response:
                finalPayload.toString(
                    "base64"
                ),

            initial_vector:
                responseIV.toString(
                    "base64"
                )
        };

        console.log("================================");
        console.log("FINAL RESPONSE");
        console.log(finalResponse);
        console.log("================================");

        return res
            .status(200)
            .json(finalResponse);

    } catch (err) {

        console.error("FLOW ERROR");
        console.error(err);

        return res.status(500).json({
            error: err.message
        });
    }
});

// =========================================
// HEALTH CHECK
// =========================================

app.get("/", (req, res) => {

    return res.send(
        "WhatsApp Flow Endpoint Running"
    );
});

// =========================================
// START SERVER
// =========================================

const PORT =
    process.env.PORT || 3000;

app.listen(PORT, () => {

    console.log("================================");
    console.log(
        "WhatsApp Flow Server Running"
    );
    console.log("PORT:", PORT);
    console.log("================================");
});
