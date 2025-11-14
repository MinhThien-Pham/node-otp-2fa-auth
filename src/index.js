// src/index.js
const server = require('./server');

const port = process.env.PORT || 5050;


const startServer = () => {
    server.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    }); 
};

startServer();