//JavaScript (Cross-Site Scripting - XSS)

const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello, ${name}</h1>`); // Unsanitized user input
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
