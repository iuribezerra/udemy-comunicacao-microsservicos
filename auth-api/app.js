import express from "express";
import checkToken from "./src/config/auth/checkToken.js";
import * as db from "./src/config/db/initialData.js";
import UserRoutes from './src/modules/user/routes/UserRoutes.js';

const app = express();
const env = process.env;
const PORT = env.PORT || 8080;

db.createInitialData();

app.use(express.json());
app.use(UserRoutes);

app.get("/api/status", (req, res) => {
    return res.status(200).json({
        service: "Auth-api",
        status: "UP",
        httpStatus: 200
    });
});

app.listen(PORT, () => {
    console.log(`Server started succesfully at port ${PORT}`);
});