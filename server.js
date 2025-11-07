require('./config/db');

const app = require('express')();
const port = process.env.PORT || 3000;

const userRoutes = require('./api/User');

const bodyParser = require('body-parser').json; 
app.use(bodyParser());

app.use('/user', userRoutes);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
}); 
