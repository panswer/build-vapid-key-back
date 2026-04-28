const crypto = require('node:crypto');
const express = require('express');

const app = express();

const port = process.env.SERVER_PORT || 3000;



app.post('/push-notification', (req, res) => {


    res.status(201).json({
    })
});

app.listen(
    port, err => {
        if (err) {
            console.log(err);
            process.exit(1);
        }

        console.log(`Server on port ${port}`);
    }
)