// main file
import express from "express";
import router from "./routes.js";
import  oidcRouter from "./oidcRoutes.js";
import  dvvRouter from "./dvvRoutes.js";

const app = express();
const port = 3000;

// Use the routes defined in the separate router file
app.use("/", router);
app.use("/", oidcRouter);
app.use("/dvv", dvvRouter);

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});