const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

const app = express();

app.use(express.json({
    limit: "5mb"
}));

// =====================================
// LOAD PRIVATE KEY
// =====================================

const privateKey = fs.readFileSync(
    "./private.pem",
    "utf8"
);

// =====================================
// FLOW SCREEN RESPONSES
// IMPORTANT:
// SCREEN NAME MUST EXIST IN FLOW
// =====================================

const SCREEN_RESPONSES = {

    PRODUCT_SELECTOR: {

        screen: "PRODUCT_SELECTOR",

        data: {

            products: [

                {
                    id: "0_mobile_phones",
                    title: "Mobile phones"
                },

                {
                    id: "1_eBook_readers",
                    title: "eBook readers"
                },

                {
                    id: "2_cameras",
                    title: "Cameras"
                }
            ]
        }
    }
};

// =====================================
// MAIN ENDPOINT
// =====================================

app.post("/", async (req, res) => {

    try {

        console.log("================================");
        console.log("INCOMING REQUEST");
        console.log(
            JSON.stringify(req.body, null, 2)
        );
        console.log("================================");

        const {
            encrypted_flow_data,
            encrypted_aes_key,
            initial_vector
        } = req.body;

        // =====================================
        // RSA DECRYPT AES KEY
        // =====================================

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

        // =====================================
        // REQUEST IV
        // =====================================

        const iv = Buffer.from(
            initial_vector,
            "base64"
        );

        // =====================================
        // ENCRYPTED FLOW DATA
        // =====================================

        const flowData = Buffer.from(
            encrypted_flow_data,
            "base64"
        );

        // =====================================
        // SPLIT AUTH TAG
        // LAST 16 BYTES
        // =====================================

        const authTag =
            flowData.slice(-16);

        const cipherText =
            flowData.slice(0, -16);

        // =====================================
        // AES-GCM DECRYPT
        // =====================================

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
        console.log("DECRYPTED DATA");
        console.log(decrypted);
        console.log("================================");

        const decryptedBody =
            JSON.parse(decrypted);

        // =====================================
        // FLOW ACTION HANDLING
        // =====================================

        let responseObj;

        if (
            decryptedBody.action === "INIT"
        ) {

            responseObj =
                SCREEN_RESPONSES
                .PRODUCT_SELECTOR;

        } else {

            responseObj = {

                screen:
                    "PRODUCT_SELECTOR",

                data: {}
            };
        }

        console.log("================================");
        console.log("RESPONSE OBJECT");
        console.log(
            JSON.stringify(
                responseObj,
                null,
                2
            )
        );
        console.log("================================");

        const responseJson =
            JSON.stringify(responseObj);

        // =====================================
        // IMPORTANT:
        // RESPONSE IV =
        // BITWISE NOT OF REQUEST IV
        // =====================================

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

        // =====================================
        // AES-GCM ENCRYPT RESPONSE
        // =====================================

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

        // =====================================
        // APPEND AUTH TAG
        // =====================================

        const finalPayload =
            Buffer.concat([
                encrypted,
                responseTag
            ]);

        // =====================================
        // FINAL RESPONSE
        // =====================================

        const finalResponse = {

            encrypted_flow_data:
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

        console.error("================================");
        console.error("FLOW ERROR");
        console.error(err);
        console.error("================================");

        return res.status(500).json({
            error: err.message
        });
    }
});

// =====================================
// HEALTH CHECK
// =====================================

app.get("/", (req, res) => {

    return res.send(
        "WhatsApp Flow Endpoint Running"
    );
});

// =====================================
// START SERVER
// =====================================

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
