const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

const app = express();

app.use(express.json({ limit: "5mb" }));

const privateKey = fs.readFileSync(
    "./private.pem",
    "utf8"
);

app.post("/", async (req, res) => {

    try {

        const {
            encrypted_flow_data,
            encrypted_aes_key,
            initial_vector
        } = req.body;

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

        const iv = Buffer.from(
            initial_vector,
            "base64"
        );

        const flowData = Buffer.from(
            encrypted_flow_data,
            "base64"
        );

        const authTag =
            flowData.slice(-16);

        const cipherText =
            flowData.slice(0, -16);

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

        console.log("Decrypted Flow Data:");
        console.log(decrypted);

        const responseObj = {
            version: "3.0",
            screen: "SUCCESS",
            data: {}
        };

        const responseJson =
            JSON.stringify(responseObj);

        const responseIV =
            crypto.randomBytes(12);

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

        const finalPayload =
            Buffer.concat([
                encrypted,
                responseTag
            ]);

        res.json({

            encrypted_response:
                finalPayload.toString(
                    "base64"
                ),

            initial_vector:
                responseIV.toString(
                    "base64"
                )
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            error: err.message
        });
    }
});

const PORT =
    process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(
        "Server running on " + PORT
    );
});
